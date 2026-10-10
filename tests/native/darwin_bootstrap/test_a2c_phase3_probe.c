/* External live process observation; not a signed installed identity witness. */
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
    struct proc_bsdinfo info;
    struct proc_fdinfo descriptors[512];
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (argc != 2) return 1;
    int pid = atoi(argv[1]);
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) ||
        proc_pidpath(pid, path, sizeof(path)) <= 0 || bytes <= 0 ||
        (size_t)bytes >= sizeof(descriptors) || bytes % sizeof(descriptors[0])) return 2;
    (void)printf("{\"pid\":%u,\"parent\":%u,\"status\":%u,\"start_sec\":%llu,\"start_usec\":%llu,\"path\":\"%s\",\"fds\":[",
                 info.pbi_pid, info.pbi_ppid, info.pbi_status,
                 (unsigned long long)info.pbi_start_tvsec, (unsigned long long)info.pbi_start_tvusec, path);
    for (size_t i = 0; i < (size_t)bytes / sizeof(descriptors[0]); i++)
        (void)printf("%s%d", i ? "," : "", descriptors[i].proc_fd);
    struct socket_fdinfo socket_info;
    int socket_bytes = proc_pidfdinfo(pid, 6, PROC_PIDFDSOCKETINFO, &socket_info, sizeof(socket_info));
    int listening = socket_bytes == sizeof(socket_info) && socket_info.psi.soi_family == AF_UNIX &&
        socket_info.psi.soi_type == SOCK_STREAM ? (socket_info.psi.soi_options & SO_ACCEPTCONN) != 0 : -1;
    (void)printf("],\"listening\":%d}\n", listening);
    return 0;
}
