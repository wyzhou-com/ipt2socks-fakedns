#define _GNU_SOURCE
#include "socks5.h"
#include "logutils.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

socks5_authreq_t g_socks5_auth_request = {
    .version = SOCKS5_VERSION,
    .mlength = 1,
    .method = SOCKS5_METHOD_NOAUTH, /* noauth by default */
};

char     g_socks5_usrpwd_request[SOCKS5_USRPWD_REQMAXLEN] = {0};
uint16_t g_socks5_usrpwd_requestlen = 0;

const socks5_ipv4req_t G_SOCKS5_UDP4_REQUEST = {
    .version = SOCKS5_VERSION,
    .command = SOCKS5_COMMAND_UDPASSOCIATE,
    .reserved = 0,
    .addrtype = SOCKS5_ADDRTYPE_IPV4,
    .ipaddr4 = 0,
    .portnum = 0,
};

const socks5_ipv6req_t G_SOCKS5_UDP6_REQUEST = {
    .version = SOCKS5_VERSION,
    .command = SOCKS5_COMMAND_UDPASSOCIATE,
    .reserved = 0,
    .addrtype = SOCKS5_ADDRTYPE_IPV6,
    .ipaddr6 = {0},
    .portnum = 0,
};

void socks5_usrpwd_request_make(const char *username, const char *password) {
    g_socks5_auth_request.method = SOCKS5_METHOD_USRPWD;

    socks5_usrpwdreq_t *usrpwdreq = (void *)g_socks5_usrpwd_request;
    usrpwdreq->version = SOCKS5_USRPWD_VERSION;

    uint8_t *usrlenptr = (void *)usrpwdreq + 1;
    *usrlenptr = strlen(username);

    char *usrbufptr = (void *)usrlenptr + 1;
    memcpy(usrbufptr, username, *usrlenptr);

    uint8_t *pwdlenptr = (void *)usrbufptr + *usrlenptr;
    *pwdlenptr = strlen(password);

    char *pwdbufptr = (void *)pwdlenptr + 1;
    memcpy(pwdbufptr, password, *pwdlenptr);

    g_socks5_usrpwd_requestlen = 1 + 1 + *usrlenptr + 1 + *pwdlenptr;
}

void socks5_proxy_request_make(void *request, const void *skaddr, const char *domain, size_t *reqlen) {
    socks5_ipv4req_t *req = request;
    req->version = SOCKS5_VERSION;
    req->command = SOCKS5_COMMAND_CONNECT;
    req->reserved = 0;

    if (domain) {
        socks5_domainreq_t *dreq = request;
        dreq->addrtype = SOCKS5_ADDRTYPE_DOMAIN;
        dreq->domain_len = strlen(domain);
        memcpy(dreq->domain_str, domain, dreq->domain_len);

        portno_t port;
        if (((skaddr4_t *)skaddr)->sin_family == AF_INET) {
            port = ((skaddr4_t *)skaddr)->sin_port;
        } else {
            port = ((skaddr6_t *)skaddr)->sin6_port;
        }
        memcpy(dreq->domain_str + dreq->domain_len, &port, 2);
        
        if (reqlen) *reqlen = sizeof(socks5_domainreq_t) + dreq->domain_len + 2;
    } else if (((skaddr4_t *)skaddr)->sin_family == AF_INET) {
        const skaddr4_t *addr = skaddr;
        req->addrtype = SOCKS5_ADDRTYPE_IPV4;
        req->ipaddr4 = addr->sin_addr.s_addr;
        req->portnum = addr->sin_port;
        if (reqlen) *reqlen = sizeof(socks5_ipv4req_t);
    } else {
        const skaddr6_t *addr = skaddr;
        socks5_ipv6req_t *req6 = (socks5_ipv6req_t *)request;
        req6->addrtype = SOCKS5_ADDRTYPE_IPV6;
        memcpy(&req6->ipaddr6, &addr->sin6_addr.s6_addr, IP6BINLEN);
        req6->portnum = addr->sin6_port;
        if (reqlen) *reqlen = sizeof(socks5_ipv6req_t);
    }
}

static inline const char* socks5_rcode2string(uint8_t rcode) {
    switch (rcode) {
        case SOCKS5_RESPCODE_SUCCEEDED: return "Succeeded";
        case SOCKS5_RESPCODE_SVRGENERR: return "General server failure";
        case SOCKS5_RESPCODE_NOTALLOWED: return "Not allowed by ruleset";
        case SOCKS5_RESPCODE_NETUNREACH: return "Network unreachable";
        case SOCKS5_RESPCODE_HOSTUNREACH: return "Host unreachable";
        case SOCKS5_RESPCODE_CONNREFUSED: return "Connection refused";
        case SOCKS5_RESPCODE_TTLEXPIRED: return "TTL expired";
        case SOCKS5_RESPCODE_COMMANDNOTSPT: return "Command not supported";
        case SOCKS5_RESPCODE_ADDRTYPENOTSPT: return "Address type not supported";
    }
    return "Unknown response code";
}

bool socks5_auth_response_check(const char *funcname, const socks5_authresp_t *response) {
    if (response->version != SOCKS5_VERSION) {
        LOGERR("[%s] response.version:%#hhx != %#x", funcname, response->version, SOCKS5_VERSION);
        return false;
    }
    if (response->method != g_socks5_auth_request.method) {
        LOGERR("[%s] response.method:%#hhx != %s", funcname, response->method, g_socks5_usrpwd_requestlen ? "USRPWD" : "NOAUTH");
        return false;
    }
    return true;
}

bool socks5_usrpwd_response_check(const char *funcname, const socks5_usrpwdresp_t *response) {
    if (response->version != SOCKS5_USRPWD_VERSION) {
        LOGERR("[%s] response.version:%#hhx != %#x", funcname, response->version, SOCKS5_USRPWD_VERSION);
        return false;
    }
    if (response->respcode != SOCKS5_USRPWD_AUTHSUCC) {
        LOGERR("[%s] response.respcode:%#hhx != AUTHSUCC", funcname, response->respcode);
        return false;
    }
    return true;
}

bool socks5_proxy_response_check(const char *funcname, const socks5_ipv4resp_t *response) {
    if (response->version != SOCKS5_VERSION) {
        LOGERR("[%s] response.version:%#hhx != %#x", funcname, response->version, SOCKS5_VERSION);
        return false;
    }
    if (response->respcode != SOCKS5_RESPCODE_SUCCEEDED) {
        LOGERR("[%s] response.respcode:%#hhx(%s) != SUCCEEDED", funcname, response->respcode, socks5_rcode2string(response->respcode));
        return false;
    }
    return true;
}
