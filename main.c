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
#include <linux/if.h>

#define ETH_HEADER_SIZE 14
#define MIN(a, b) ((a) < (b) ? (a) : (b))

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

void signal_handler(int sig)
{
    if (sig == SIGINT)
        _exit(EXIT_SUCCESS);
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
    int rc = 0;
    const char separator[] = "\n";
    char line[40];

    while (!feof(cached_ips)) {
        if (!fgets(line, sizeof(line), cached_ips))
            continue;

        line[strcspn(line, separator)] = 0;
        if (strcmp(line, s))
            continue;

        rc = 1;

        break;
    }

    if (fseek(cached_ips, 0, SEEK_SET)) {
        printf("Error: fseek is_ip_saved error: %s\n", strerror(errno));
        return -1;
    }

    return rc;
}
/* ********************** */

void set_limits(int req_lim, int tim_lim)
{
    api_lim.X_Rl = req_lim;
    api_lim.X_Ttl = tim_lim + 1;
}

int return_value_by_key(const char *headers, const char *key, char *res, size_t size)
{
    char *key_p = strstr(headers, key);

    if (!key_p)
        return -1;

    strncpy(res, strchr(key_p, ':') + 1, MIN(strchr(key_p, '\n') - strchr(key_p, ':'), size));
    return 0;
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

    char xrl[100];
    char xttl[100];

    curl_loc = curl_easy_init();
    if ((curl_loc = curl_easy_init()) == NULL) {
        printf("Error: curl_loc initialization error\n");
        return -1;
    }

    curl_easy_setopt(curl_loc, CURLOPT_URL, host);
    curl_easy_setopt(curl_loc, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_loc, CURLOPT_HEADERFUNCTION, write_callback);

    curl_easy_setopt(curl_loc, CURLOPT_WRITEDATA, &response_chunk);
    curl_easy_setopt(curl_loc, CURLOPT_HEADERDATA, &header_chunk);

    res = curl_easy_perform(curl_loc);
    if (res != CURLE_OK) {
        printf("Error: curl error: %s\n", curl_easy_strerror(res));
        return -1;
    }

    if (!return_value_by_key(header_chunk.response, "X-Rl", xrl, sizeof(xrl)) &&
        !return_value_by_key(header_chunk.response, "X-Ttl", xttl, sizeof(xttl)))
        set_limits(atoi(xrl), atoi(xttl));

    *data = malloc(response_chunk.size);
    memcpy(*data, response_chunk.response, response_chunk.size);

    free(response_chunk.response);
    free(header_chunk.response);

    curl_easy_cleanup(curl_loc);
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

char *get_line(const char *in, char *out, int size)
{
    char *p;
    char *end = strchr(in, '\0');

    p = strchr(in, '\n');
    if (!p)
        p = end;

    strncpy(out, in, MIN(size, p - in));
    out[p - in] = '\0';

    return p + (*p == '\n' ? 1 : 0);
}

int get_location_by_ip(const char *ip, struct location *loc_res)
{
    char host[1024];
    char *resp;
    char *p;
    char line[100];

    snprintf(host, sizeof(host), "http://ip-api.com/line/%s?fields=status,message,continent,country,regionName,city,timezone,currency,org,mobile,proxy,query", ip);
    if (send_request(host, &resp) < 0)
        return -1;

    p = resp;

    p = get_line(p, line, sizeof(line));
    if (!strcmp(line, "fail")) {
        strcpy(loc_res->status, "fail");

        p = get_line(p, line, sizeof(line));
        strcpy(loc_res->message, line);

        p = get_line(p, line, sizeof(line));
        strcpy(loc_res->query, line);

        return 0;
    }

    strcpy(loc_res->status, "success");

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->continent, line);

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->country, line);

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->regionName, line);

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->city, line);

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->timezone, line);

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->currency, line);

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->organization_name, line);

    p = get_line(p, line, sizeof(line));
    loc_res->proxy = !strcmp(line, "true") ? true : false;

    p = get_line(p, line, sizeof(line));
    loc_res->mobile = !strcmp(line, "true") ? true : false;

    p = get_line(p, line, sizeof(line));
    strcpy(loc_res->query, line);

    free(resp);

    return 0;
}

void my_packet_handler(const u_char *packet, unsigned long device_ip)
{
    struct ether_header *eth_header;
    struct ip *ip_header;
    char external_ip[INET_ADDRSTRLEN];
    struct location loc;
    struct in_addr *external_binary_ip;

    if (!packet)
        return;

    eth_header = (struct ether_header *) packet;
    ip_header = (struct ip *)(packet + ETH_HEADER_SIZE);

    /* IPv4 */
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return;

    external_binary_ip = (ip_header->ip_src.s_addr != device_ip) ? &ip_header->ip_src : &ip_header->ip_dst;

    if (!inet_ntop(AF_INET, external_binary_ip, external_ip, sizeof(external_ip))) {
        char err_msg[256];

        snprintf(err_msg, sizeof(err_msg), "inet_ntop: packet handler %lu %s\n", (unsigned long)external_binary_ip->s_addr, external_ip);
        perror(err_msg);

        return;
    }

    if (is_ip_saved(external_ip))
        return;

    if (get_location_by_ip(external_ip, &loc))
        printf("Error: get location ip\n");

    strcat(external_ip, "\n");
    cached_ip_insert(external_ip);

    print_ip_location(&loc);
}

int main(int argc, char *argv[])
{
    char device[IFNAMSIZ];
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr packet_header = {0};
    char *filter = "";
    struct bpf_program fp; /*compiled filter */
    bpf_u_int32 netp; /* ip address of interface */
    bpf_u_int32 maskp; /* subnet mask of interface */
    pcap_if_t *it_device = NULL;

    api_lim.X_Rl = -1;
    api_lim.X_Ttl = -1;

    signal(SIGINT, signal_handler);

    cached_ips = tmpfile();
    if (!cached_ips) {
        printf("Error: Cannot open temporary file\n");
        exit(EXIT_FAILURE);
    }

    if (!pcap_findalldevs(&it_device, error_buffer)
        && !it_device) {
        printf("Error: finding device: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    strcpy(device, it_device->name);
    pcap_freealldevs(it_device);

    handle = pcap_open_live(device, BUFSIZ, 0, 0, error_buffer);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("Error datalink: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(device, &netp, &maskp, error_buffer)) {
        printf("Error lookupnet: %s", error_buffer);
        exit(EXIT_FAILURE);
    }

    printf("device name: %s, ip: %s\n", device, inet_ntoa((struct in_addr){.s_addr = netp}));

    if (pcap_compile(handle, &fp, filter, 0, maskp)) {
        printf("Error: %s", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp)) {
        printf("Error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_freecode(&fp);
    while (1) {
        const u_char *packet = pcap_next(handle, &packet_header);

        my_packet_handler(packet, netp);

        if (api_lim.X_Rl == 0 && api_lim.X_Ttl > 0)
            sleep(api_lim.X_Ttl);
    }

    pcap_close(handle);
    fclose(cached_ips);

    return EXIT_SUCCESS;
}
