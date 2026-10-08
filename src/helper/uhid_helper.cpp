// SPDX-License-Identifier: LGPL-2.1-or-later
//
// kpasskey-uhid-helper: the only component with access to /dev/uhid.
//
// Started by systemd per connection (kpasskey-uhid.socket, Accept=yes) with the
// client socket on stdin, running as the unprivileged system user
// "kpasskey-uhid" (udev gives that group /dev/uhid). It
//   1. identifies the peer via SO_PEERCRED,
//   2. requires that this uid owns an active, local logind session,
//   3. allows one device per uid (flock),
//   4. creates exactly ONE fixed FIDO HID device (no keyboards, no other
//      descriptors are possible through this helper),
//   5. relays raw 64 byte reports between the socket and the device,
//   6. destroys the device as soon as the socket closes or the session stops
//      being active.
// Deliberately no CBOR/CTAP parsing here: the helper only checks lengths.

#include "hid/fido_descriptor.h"

#include <systemd/sd-login.h>

#include <cerrno>
#include <cstdarg>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/uhid.h>
#include <poll.h>
#include <string>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace kpasskey;

namespace {

constexpr int SocketFd = STDIN_FILENO;

void logMsg(const char *prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void logMsg(const char *prio, const char *fmt, ...)
{
    // stderr goes to the journal; "<N>" prefixes set the syslog priority.
    va_list ap;
    va_start(ap, fmt);
    std::fputs(prio, stderr);
    std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
    va_end(ap);
}

bool writeAll(int fd, const void *data, size_t size)
{
    const char *p = static_cast<const char *>(data);
    while (size > 0) {
        const ssize_t n = ::write(fd, p, size);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        p += n;
        size -= size_t(n);
    }
    return true;
}

// True if `uid` owns the active graphical session and it is local.
bool uidIsActiveLocally(uid_t uid)
{
    char *session = nullptr;
    if (sd_uid_get_display(uid, &session) < 0 || !session) {
        return false;
    }
    const bool ok = sd_session_is_active(session) > 0 && sd_session_is_remote(session) == 0;
    std::free(session);
    return ok;
}

bool createDevice(int uhid, uid_t uid)
{
    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    std::strncpy(reinterpret_cast<char *>(ev.u.create2.name), fido::DeviceName, sizeof(ev.u.create2.name) - 1);
    std::strncpy(reinterpret_cast<char *>(ev.u.create2.phys), "kpasskey-uhid-helper", sizeof(ev.u.create2.phys) - 1);
    std::snprintf(reinterpret_cast<char *>(ev.u.create2.uniq), sizeof(ev.u.create2.uniq), "kpasskey-uid%u", unsigned(uid));
    std::memcpy(ev.u.create2.rd_data, fido::ReportDescriptor, sizeof(fido::ReportDescriptor));
    ev.u.create2.rd_size = sizeof(fido::ReportDescriptor);
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = fido::Vendor;
    ev.u.create2.product = fido::Product;
    return writeAll(uhid, &ev, sizeof(ev));
}

bool sendInput(int uhid, const unsigned char *report)
{
    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = fido::ReportSize;
    std::memcpy(ev.u.input2.data, report, fido::ReportSize);
    return writeAll(uhid, &ev, sizeof(ev));
}

// Returns false when the device is gone.
bool handleUhidEvent(int uhid)
{
    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    const ssize_t n = ::read(uhid, &ev, sizeof(ev));
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
        return true;
    }
    if (n <= 0) {
        return false;
    }
    switch (ev.type) {
    case UHID_OUTPUT: {
        const unsigned char *data = ev.u.output.data;
        size_t size = ev.u.output.size;
        if (size == fido::ReportSize + 1) { // leading report ID 0
            ++data;
            --size;
        }
        if (size == fido::ReportSize && !writeAll(SocketFd, data, size)) {
            return false;
        }
        return true;
    }
    case UHID_GET_REPORT: {
        uhid_event reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.type = UHID_GET_REPORT_REPLY;
        reply.u.get_report_reply.id = ev.u.get_report.id;
        reply.u.get_report_reply.err = EIO;
        return writeAll(uhid, &reply, sizeof(reply));
    }
    case UHID_SET_REPORT: {
        uhid_event reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.type = UHID_SET_REPORT_REPLY;
        reply.u.set_report_reply.id = ev.u.set_report.id;
        reply.u.set_report_reply.err = EIO;
        return writeAll(uhid, &reply, sizeof(reply));
    }
    default: // START, STOP, OPEN, CLOSE
        return true;
    }
}

} // namespace

int main()
{
    std::signal(SIGPIPE, SIG_IGN);

    ucred cred {};
    socklen_t len = sizeof(cred);
    if (getsockopt(SocketFd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        logMsg("<3>", "stdin is not a Unix socket: %s", std::strerror(errno));
        return 2;
    }
    if (cred.uid == 0) {
        logMsg("<4>", "refusing root peer (pid %d)", int(cred.pid));
        return 3;
    }
    if (!uidIsActiveLocally(cred.uid)) {
        logMsg("<4>", "uid %u has no active local session; refusing (pid %d)", unsigned(cred.uid), int(cred.pid));
        return 3;
    }

    // One device per user.
    const std::string lockPath = "/run/kpasskey/uid-" + std::to_string(cred.uid) + ".lock";
    const int lock = ::open(lockPath.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || ::flock(lock, LOCK_EX | LOCK_NB) != 0) {
        logMsg("<4>", "uid %u already has a device (or lock failed: %s)", unsigned(cred.uid), std::strerror(errno));
        return 4;
    }

    const int uhid = ::open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (uhid < 0) {
        logMsg("<3>", "cannot open /dev/uhid: %s", std::strerror(errno));
        return 5;
    }
    if (!createDevice(uhid, cred.uid)) {
        logMsg("<3>", "UHID_CREATE2 failed: %s", std::strerror(errno));
        return 5;
    }

    sd_login_monitor *monitor = nullptr;
    if (sd_login_monitor_new("session", &monitor) < 0) {
        logMsg("<3>", "sd_login_monitor_new failed");
        return 6;
    }
    if (!writeAll(SocketFd, fido::HelperHello, sizeof(fido::HelperHello))) {
        return 7;
    }
    logMsg("<6>", "FIDO device created for uid %u (pid %d)", unsigned(cred.uid), int(cred.pid));

    unsigned char buffer[fido::ReportSize];
    size_t filled = 0;
    bool running = true;
    while (running) {
        pollfd fds[3] = {
            {SocketFd, POLLIN, 0},
            {uhid, POLLIN, 0},
            {sd_login_monitor_get_fd(monitor), short(sd_login_monitor_get_events(monitor)), 0},
        };
        if (::poll(fds, 3, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            const ssize_t n = ::read(SocketFd, buffer + filled, sizeof(buffer) - filled);
            if (n <= 0 && !(n < 0 && errno == EINTR)) {
                running = false; // client closed: tear down
            } else if (n > 0) {
                filled += size_t(n);
                if (filled == sizeof(buffer)) {
                    running = sendInput(uhid, buffer);
                    filled = 0;
                }
            }
        }
        if (running && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            running = handleUhidEvent(uhid);
        }
        if (running && fds[2].revents) {
            sd_login_monitor_flush(monitor);
            if (!uidIsActiveLocally(cred.uid)) {
                logMsg("<5>", "session of uid %u no longer active; removing device", unsigned(cred.uid));
                running = false;
            }
        }
    }

    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    writeAll(uhid, &ev, sizeof(ev));
    ::close(uhid);
    sd_login_monitor_unref(monitor);
    // The lock file is intentionally not unlinked: unlinking a held lock file
    // would let two instances lock different inodes.
    logMsg("<6>", "FIDO device for uid %u removed", unsigned(cred.uid));
    return 0;
}
