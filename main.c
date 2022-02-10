#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <signal.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <stddef.h>
#include <fcntl.h>

#define ETH_HEADER_SIZE 14

/*
 * В следующих сериях:
    3. Написать для rarp, ipv6
    13. Заменить atoi на strtol
    14. тесты
    15. таймер
*/

FILE *cached_ips;
pcap_t *handle;

struct location {
    char status[10];
    char message[25];
    char continent[25];
    char country[60];
    char regionName[90];
    char city[90];
    char district[90];
    char timezone[50];
    char currency[10];
    char organization_name[100];
    char query[50];
    bool proxy;
    bool mobile;
};

struct api_limits {
    long X_Rl;
    long X_Ttl;
} api_lim;

struct memory {
    char *response;
    size_t size;
};

void sigint_signal(int sig)
{
    if (sig == SIGINT) {
        pcap_close(handle);
        _exit(1);
    }
}

/* ****** file operations ****** */
int cached_ip_insert(const char *s)
{
    if (fseek(cached_ips, 0L, SEEK_END) != 0) {
        printf("Error: fseek push error: %s\n", strerror(errno));
        return -1;
    }

    if (fputs(s, cached_ips) == EOF) {
        if (fseek(cached_ips, 0L, SEEK_SET) != 0) {
            printf("Error: fseek push error: %s\n", strerror(errno));
            return -1;
        }
        printf("Error: unable to save %s\n", s);
        return -1;
    }

    if (fseek(cached_ips, 0L, SEEK_SET) != 0) {
        printf("Error: fseek push error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int is_ip_saved(char *s)
{
    const char separator[] = "\n";
    char line[40];
    while (!feof(cached_ips)) {
        if (fgets(line, sizeof(line), cached_ips)) {
            line[strcspn(line, separator)] = 0;
            if (strcmp(line, s) == 0) {
                if (fseek(cached_ips, 0L, SEEK_SET) != 0) {
                    printf("Error: fseek is_ip_saved error: %s\n", strerror(errno));
                    return -1;
                }
                return 1;
            }
        }
    }

    if (fseek(cached_ips, 0, SEEK_SET) != 0) {
        printf("Error: fseek is_ip_saved error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}
/* ********************** */

void set_limits(int req_lim, int tim_lim)
{
    api_lim.X_Rl = req_lim;
    api_lim.X_Ttl = tim_lim + 1;
}

int return_value_by_key(const char *headers, const char *key, char *res)
{
    char *key_p = strstr(headers, key);

    if (NULL != key_p) {
        strncpy(res, strchr(key_p, ':') + 1, strchr(key_p, '\n') - strchr(key_p, ':'));
        return 0;
    }

    return -1;
}

size_t write_callback(char *data, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *) userdata;
    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (ptr == NULL)
        return 0;

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;
    return realsize;
}

int send_request(char *host, char **data)
{
    CURLcode res;
    CURL *curl_loc;

    struct memory response_chunk = {0};
    struct memory header_chunk = {0};

    curl_loc = curl_easy_init();
    if ((curl_loc = curl_easy_init()) == NULL) {
        printf("Error: curl_loc initialization error\n");
        return -1;
    }

    char xrl[100];
    char xttl[100];

    curl_easy_setopt(curl_loc, CURLOPT_URL, host);
    curl_easy_setopt(curl_loc, CURLOPT_WRITEDATA, (void *)&response_chunk);
    curl_easy_setopt(curl_loc, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_loc, CURLOPT_HEADERFUNCTION, write_callback);
    curl_easy_setopt(curl_loc, CURLOPT_HEADERDATA, (void *)&header_chunk);

    res = curl_easy_perform(curl_loc);
    if (res != CURLE_OK) {
        printf("Error: curl error: %s\n", curl_easy_strerror(res));
        return -1;
    }

    if (0 == return_value_by_key(header_chunk.response, "X-Rl", xrl))
        if (0 == return_value_by_key(header_chunk.response, "X-Ttl", xttl))
            set_limits(atoi(xrl), atoi(xttl));

    *data = (char *)malloc(strlen(response_chunk.response) + 1);
    strcpy(*data, response_chunk.response);

    curl_easy_cleanup(curl_loc);
    curl_loc = NULL;

    return 0;
}

void print_ip_location(const struct location *loc_info)
{
    if (strcmp(loc_info->status, "fail") == 0) {
        printf("------ Error: ------\n");
        printf("status: %s\n", loc_info->status);
        printf("error failed: %s\n", loc_info->message);
        printf("ip: %s\n", loc_info->query);
        return;
    }

    printf("------ Response: ------\n");
    printf("status: %s\n", loc_info->status);
    printf("continent: %s\n", loc_info->continent);
    printf("country: %s\n", loc_info->country);
    printf("regionName: %s\n", loc_info->regionName);
    printf("city: %s\n", loc_info->city);
    printf("timezone: %s\n", loc_info->timezone);
    printf("currency: %s\n", loc_info->currency);
    printf("org: %s\n", loc_info->organization_name);
    printf("proxy: %d\n", loc_info->proxy);
    printf("mobile: %d\n", loc_info->mobile);
    printf("ip: %s\n", loc_info->query);
}

char *get_line(const char *data, int line_size, char *line)
{
    int len;
    char *line_end;

    if ((line_end = strchr(data, '\n')) == NULL)
        return 0;

    len = line_end - data;
    if (len > line_size)
        return 0;

    strncpy(line, data, len);
    line[len] = '\0';

    return (char *)data + len + 1;
}

int get_location_by_ip(const char *ip, struct location *loc_res)
{
    char host[1024];
    char *response;

    const char separator[] = "\n";
    int line_size = 100;
    char line[line_size];

    sprintf(host, "http://ip-api.com/line/%s?fields=status,message,continent,country,regionName,city,timezone,currency,org,mobile,proxy,query", ip);
    if (send_request(host, &response) < 0) {
        printf("Error: get location by ip\n");
        return -1;
    }

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    if (strcmp(line,"fail") == 0) {
        strcpy(loc_res->status, "fail");

        if ((response = get_line(response, line_size, line)) <= 0)
            return -1;
        strcpy(loc_res->message, line);

        if ((response = get_line(response, line_size, line)) <= 0)
            return -1;
        strcpy(loc_res->query, line);

        return 0;
    }
    strcpy(loc_res->status, "success");

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->continent, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->country, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->regionName, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->city, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->timezone, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->currency, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->organization_name, line);

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    loc_res->proxy = strcmp(line, "true") == 0 ? true : false;

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    loc_res->mobile = strcmp(line, "true") == 0 ? true : false;

    if ((response = get_line(response, line_size, line)) <= 0)
        return -1;
    strcpy(loc_res->query, line);

    free(response);

    return 0;
}

void my_packet_handler(const u_char *packet, unsigned long device_ip)
{
    struct ether_header *eth_header;
    struct ip *ip_header;
    char external_ip[100];
    struct location loc;

    eth_header = (struct ether_header *) packet;
    ip_header = (struct ip *)(packet + ETH_HEADER_SIZE);

    /* IPv4 */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct in_addr external_binary_ip = (ip_header->ip_src.s_addr != device_ip) ? ip_header->ip_src : ip_header->ip_dst;
        if (inet_ntop(AF_INET, &external_binary_ip, external_ip, sizeof(external_ip)) == NULL) {
            perror("inet_ntop");
            printf("packet handler %ul %s\n", external_binary_ip, external_ip);
            return;
        }

        if (!is_ip_saved(external_ip)) {

            if (get_location_by_ip(external_ip, &loc)) {
                printf("Error: get location ip\n");
            }

            strcat(external_ip, "\n");
            cached_ip_insert(external_ip);

            print_ip_location(&loc);
        }
    }

        /* here should be ipv6 processing AF_INET6 */
//    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
//         printf("ARP\n");
//         printf ("Source: %d.%d.%d.%d\t\tDestination: %d.%d.%d.%d\n",
//             arp_packet->arp_spa[0],
//             arp_packet->arp_spa[1],
//             arp_packet->arp_spa[2],
//             arp_packet->arp_spa[3],
//             arp_packet->arp_tpa[0],
//             arp_packet->arp_tpa[1],
//             arp_packet->arp_tpa[2],
//             arp_packet->arp_tpa[3]);
//     } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
//         printf("Reverse ARP\n");
//     }
}

int main(int argc, char *argv[])
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr packet_header;
    char *filter = "";
    char my_device_ip[40];
    const u_char *packet;
    struct bpf_program fp; /*compiled filter */
    bpf_u_int32 netp; /* ip address of interface */
    bpf_u_int32 maskp; /* subnet mask of interface */
    struct in_addr address;

    api_lim.X_Rl = -1;
    api_lim.X_Ttl = -1;

    cached_ips = tmpfile();

    if (!cached_ips) {
        printf("Error: Cannot open temporary file\n");
        exit(EXIT_FAILURE);
    }

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error: finding device: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(
        device,
        BUFSIZ,
        0,
        0,
        error_buffer
    );
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sigint_signal);

    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("Error: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(device, &netp, &maskp, error_buffer) == -1) {
        printf("Error: %s", error_buffer);
        exit(EXIT_FAILURE);
    }

    address.s_addr = netp;
    strcpy(my_device_ip, inet_ntoa(address));
    printf("ip: %s\n", my_device_ip);
    if (my_device_ip == NULL) {
        printf("inet_ntoa: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter, 0, maskp) == -1) {
        printf("Error: %s", pcap_geterr);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_freecode(&fp);

    while (1) {
        packet = pcap_next(handle, &packet_header);
        if (packet)
            my_packet_handler(packet, netp);

        if (api_lim.X_Rl == 0)
            if (api_lim.X_Ttl > 0)
                sleep(api_lim.X_Ttl);
    }

    return 0;
}
