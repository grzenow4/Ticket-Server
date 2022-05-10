#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <vector>

#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFFER_SIZE     65507
#define PORT_DEFAULT    2022
#define TIMEOUT_DEFAULT 5
#define TIMEOUT_MAX     86400

#define EVENT_ID_MAX 999999
#define RES_ID_MIN   999999

#define GET_EVENTS  1
#define EVENTS      2
#define GET_RES     3
#define RESERVATION 4
#define GET_TICKETS 5
#define TICKETS     6
#define BAD_REQUEST 255

#define MSG_ID_SIZE      1
#define DESC_LEN_SIZE    1
#define TICKET_CNT_SIZE  2
#define EVENT_ID_SIZE    4
#define RES_ID_SIZE      4
#define COOKIE_SIZE      48
#define COOKIE_ASCII_MIN 33
#define COOKIE_ASCII_MAX 126
#define EXP_TIME_SIZE    8
#define TICKET_SIZE      7

char shared_buffer[BUFFER_SIZE];
std::string next_ticket = "0000000";

typedef struct EventInfo {
    char description_length;
    std::string description;
    uint16_t ticket_count;
} EventInfo;

typedef struct ReservationInfo {
    uint32_t event_id;
    uint16_t ticket_count;
    std::string cookie;
    uint64_t expiration_time;
    std::vector<std::string> tickets;
    bool tickets_sent;
} ReservationInfo;

void fatal(const char *fmt, ...) {
    va_list fmt_args;
    fprintf(stderr, "Error: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

bool is_path_exist(char *s) {
    struct stat buffer;
    return (stat (s, &buffer) == 0);
}

char* read_filename(char *string) {
    if (!is_path_exist(string)) {
        fatal("%s path does not exist", string);
    }
    return string;
}

uint16_t read_port(char *string) {
    errno = 0;
    char *endptr = NULL;
    unsigned long port = strtoul(string, &endptr, 10);
    if (errno != 0 || port > UINT16_MAX || string == endptr) {
        fatal("%s is not a valid port number", string);
    }
    return (uint16_t) port;
}

uint32_t read_timeout(char *string) {
    errno = 0;
    char *endptr = NULL;
    unsigned long timeout = strtoul(string, &endptr, 10);
    if (errno != 0 || timeout > TIMEOUT_MAX || timeout == 0 || string == endptr) {
        fatal("%s is not a valid timeout value", string);
    }
    return (uint32_t) timeout;
}

int bind_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        fatal("socket() failed");
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    if (bind(socket_fd, (struct sockaddr *) &server_address,(socklen_t) sizeof(server_address)) < 0) {
        fatal("bind() failed");
    }

    return socket_fd;
}

size_t read_message(int socket_fd, struct sockaddr_in *client_address, char *buffer, size_t max_length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);
    if (len < 0 && errno != 0) {
        fatal("recvfrom() failed");
    }
    return (size_t) len;
}

void send_message(int socket_fd, const struct sockaddr_in *client_address, const char *message, size_t length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, flags,
                                 (struct sockaddr *) client_address, address_length);
    if (sent_length != (ssize_t) length) {
        fatal("sendto() failed");
    }
}

uint64_t swap_endian_64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

uint32_t read_event_or_reservation_id() {
   return uint32_t ((unsigned char) (shared_buffer[1]) << 24 |
                    (unsigned char) (shared_buffer[2]) << 16 |
                    (unsigned char) (shared_buffer[3]) << 8 |
                    (unsigned char) (shared_buffer[4]));
}

uint16_t read_ticket_count() {
    return uint16_t ((unsigned char)(shared_buffer[5]) << 8 |
                     (unsigned char)(shared_buffer[6]));
}

std::string read_cookie() {
    std::string cookie = "";
    cookie.reserve(COOKIE_SIZE);
    for (int i = 0; i < COOKIE_SIZE; i++) {
        char c = shared_buffer[i + MSG_ID_SIZE + RES_ID_SIZE];
        if (!(c >= COOKIE_ASCII_MIN && c <= COOKIE_ASCII_MAX))
            return "";
        cookie += c;
    }
    return cookie;
}

std::string generate_ticket() {
    std::string ticket;
    ticket.reserve(TICKET_SIZE);
    ticket = next_ticket;

    for (int i = 0; i < TICKET_SIZE; i++) {
        char c = next_ticket[i];
        if (c == '9') {
            next_ticket[i] = 'A';
            break;
        } else if (c == 'Z') {
            next_ticket[i] = '0';
        } else {
            next_ticket[i]++;
            break;
        }
    }

    return ticket;
}

std::string generate_cookie() {
    std::string cookie;
    cookie.reserve(COOKIE_SIZE);
    for (int i = 0; i < COOKIE_SIZE; i++) {
        cookie += ((rand() % (COOKIE_ASCII_MAX - COOKIE_ASCII_MIN + 1)) + COOKIE_ASCII_MIN);
    }
    return cookie;
}

std::string bad_request_event(uint32_t event_id, size_t *length) {
    std::string message(MSG_ID_SIZE + EVENT_ID_SIZE, 0);
    message[0] = BAD_REQUEST;
    *length = 1;

    event_id = htonl(event_id);
    memcpy(&message[*length], &event_id, EVENT_ID_SIZE);
    *length += EVENT_ID_SIZE;

    return message;
}

std::string bad_request_reservation(uint32_t reservation_id, size_t *length) {
    std::string message(MSG_ID_SIZE + RES_ID_SIZE, 0);
    message[0] = BAD_REQUEST;
    *length = 1;

    reservation_id = htonl(reservation_id);
    memcpy(&message[*length], &reservation_id, RES_ID_SIZE);
    *length += RES_ID_SIZE;

    return message;
}

std::string get_events(std::map<uint32_t, EventInfo> events, size_t *length) {
    std::string message(BUFFER_SIZE, 0);
    message[0] = EVENTS;
    *length = 1;

    for (auto &pair : events) {
        uint32_t event_id = pair.first;
        EventInfo info = pair.second;
        size_t next_event_len = EVENT_ID_SIZE + TICKET_CNT_SIZE + DESC_LEN_SIZE + info.description_length;

        if (*length + next_event_len > BUFFER_SIZE) {
            continue;
        }

        event_id = htonl(event_id);
        memcpy(&message[*length], &event_id, EVENT_ID_SIZE);
        *length += EVENT_ID_SIZE;

        uint16_t ticket_count = htons(info.ticket_count);
        memcpy(&message[*length], &ticket_count, TICKET_CNT_SIZE);
        *length += TICKET_CNT_SIZE;

        memcpy(&message[*length], &info.description_length, DESC_LEN_SIZE);
        *length += DESC_LEN_SIZE;

        strncpy(&message[*length], info.description.c_str(), info.description_length);
        *length += info.description_length;
    }

    return message;
}

std::string reserve_tickets(std::map<uint32_t, EventInfo> *events,
                            std::map<uint32_t, ReservationInfo> *reservations,
                            uint32_t event_id,
                            uint16_t ticket_count,
                            size_t *length,
                            uint32_t timeout) {
    std::string message(BUFFER_SIZE, 0);
    message[0] = RESERVATION;
    *length = 1;

    auto event = events->find(event_id);
    if (event == events->end() ||
        ticket_count == 0 ||
        event->second.ticket_count < ticket_count ||
        ticket_count * TICKET_SIZE > BUFFER_SIZE - MSG_ID_SIZE - RES_ID_SIZE - TICKET_CNT_SIZE) {
        return bad_request_event(event_id, length);
    }

    event->second.ticket_count -= ticket_count;

    std::vector<std::string> tickets(ticket_count);
    for (size_t i = 0; i < ticket_count; i++) {
        tickets[i] = generate_ticket();
    }

    ReservationInfo res_info = {.event_id = event_id,
                                .ticket_count = ticket_count,
                                .cookie = generate_cookie(),
                                .expiration_time = (uint64_t) time(0) + timeout,
                                .tickets = tickets,
                                .tickets_sent = false};

    uint32_t reservation_id = RES_ID_MIN + reservations->size();
    reservations->insert({reservation_id, res_info});

    reservation_id = htonl(reservation_id);
    memcpy(&message[*length], &reservation_id, RES_ID_SIZE);
    *length += RES_ID_SIZE;

    event_id = htonl(event_id);
    memcpy(&message[*length], &event_id, EVENT_ID_SIZE);
    *length += EVENT_ID_SIZE;

    ticket_count = htons(ticket_count);
    memcpy(&message[*length], &ticket_count, TICKET_CNT_SIZE);
    *length += TICKET_CNT_SIZE;

    strncpy(&message[*length], res_info.cookie.c_str(), COOKIE_SIZE);
    *length += COOKIE_SIZE;

    uint64_t expiration_time =  swap_endian_64(res_info.expiration_time);
    memcpy(&message[*length], &expiration_time, EXP_TIME_SIZE);
    *length += EXP_TIME_SIZE;

    return message;
}

std::string get_tickets(std::map<uint32_t, ReservationInfo> *reservations,
                        uint32_t reservation_id,
                        std::string cookie,
                        size_t *length) {
    std::string message(BUFFER_SIZE, 0);
    message[0] = TICKETS;
    *length = 1;

    auto reservation = reservations->find(reservation_id);
    if (reservation == reservations->end() ||
        cookie.compare(reservation->second.cookie) != 0) {
        return bad_request_reservation(reservation_id, length);
    }

    reservation->second.tickets_sent = true;

    reservation_id = htonl(reservation_id);
    memcpy(&message[*length], &reservation_id, RES_ID_SIZE);
    *length += RES_ID_SIZE;

    uint16_t ticket_count = htons(reservation->second.ticket_count);
    memcpy(&message[*length], &ticket_count, TICKET_CNT_SIZE);
    *length += TICKET_CNT_SIZE;

    for (size_t i = 0; i < reservation->second.ticket_count; i++) {
        strncpy(&message[*length], reservation->second.tickets[i].c_str(), TICKET_SIZE);
        *length += TICKET_SIZE;
    }

    return message;
}

void check_reservations_timeouts(std::map<uint32_t, EventInfo> *events,
                                 std::map<uint32_t, ReservationInfo> *reservations,
                                 uint64_t time) {
    std::vector<uint32_t> res_to_erase;

    for (auto &reservation : *reservations) {
        if (!reservation.second.tickets_sent && time > reservation.second.expiration_time) {
            events->find(reservation.second.event_id)->second.ticket_count += reservation.second.ticket_count;
            res_to_erase.push_back(reservation.first);
        }
    }

    for (auto &r : res_to_erase) {
        reservations->erase(r);
    }
}

int main(int argc, char *argv[]) {
    std::vector<bool> passed = {false, false, false};
    char *filename = NULL;
    uint16_t port = PORT_DEFAULT;
    uint32_t timeout = TIMEOUT_DEFAULT;

    for (int i = 1; i < argc; i += 2) {
        if (i == argc - 1) {
            fatal("Usage: %s -f <file path> -p <port> -t <timeout>", argv[0]);
        }

        if (strcmp(argv[i], "-f") == 0 && !passed[0]) {
            filename = read_filename(argv[i + 1]);
            passed[0] = true;
        } else if (strcmp(argv[i], "-p") == 0 && !passed[1]) {
            port = read_port(argv[i + 1]);
            passed[1] = true;
        } else if (strcmp(argv[i], "-t") == 0 && !passed[2]) {
            timeout = read_timeout(argv[i + 1]);
            passed[2] = true;
        } else {
            fatal("Usage: %s -f <file path> -p <port> -t <timeout>", argv[0]);
        }
    }

    if (!passed[0]) {
        fatal("Usage: %s -f <file path> -p <port> -t <timeout>", argv[0]);
    }

    std::map<uint32_t, EventInfo> events;
    std::map<uint32_t, ReservationInfo> reservations;

    std::ifstream file(filename);
    uint32_t idx = 0;
    std::string line;
    while (getline(file, line)) {
        EventInfo info;
        info.description_length = line.length();
        info.description = line;
        getline(file, line);
        unsigned long count = strtoul(line.c_str(), NULL, 10);
        info.ticket_count = (uint16_t) count;
        events.insert({idx, info});
        idx++;
    }

    int socket_fd = bind_socket(port);
    printf("Listening on port %u\n", port);

    struct sockaddr_in client_address;
    size_t read_length;
    while (true) {
        read_length = read_message(socket_fd, &client_address, shared_buffer, BUFFER_SIZE);
        char* client_ip = inet_ntoa(client_address.sin_addr);
        uint16_t client_port = ntohs(client_address.sin_port);
        printf("Received message from client %s:%u\n", client_ip, client_port);
        uint64_t curr_time = time(0);
        size_t length = 0;

        if (shared_buffer[0] == GET_EVENTS && read_length == MSG_ID_SIZE) {
            check_reservations_timeouts(&events, &reservations, curr_time);
            std::string message = get_events(events, &length);
            send_message(socket_fd, &client_address, message.c_str(), length);
        } else if (shared_buffer[0] == GET_RES && read_length == MSG_ID_SIZE + EVENT_ID_SIZE + TICKET_CNT_SIZE) {
            uint32_t event_id = read_event_or_reservation_id();
            uint16_t ticket_count = read_ticket_count();
            check_reservations_timeouts(&events, &reservations, curr_time);
            std::string message = reserve_tickets(&events, &reservations, event_id, ticket_count, &length, timeout);
            send_message(socket_fd, &client_address, message.c_str(), length);
        } else if (shared_buffer[0] == GET_TICKETS && read_length == MSG_ID_SIZE + RES_ID_SIZE + COOKIE_SIZE) {
            uint32_t reservation_id = read_event_or_reservation_id();
            std::string cookie = read_cookie();
            check_reservations_timeouts(&events, &reservations, curr_time);
            std::string message = get_tickets(&reservations, reservation_id, cookie, &length);
            send_message(socket_fd, &client_address, message.c_str(), length);
        }
    }

    if (close(socket_fd) < 0) {
        fatal("socket close() failed");
    }

    return 0;
}
