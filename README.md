# DNShit

Proxy DNS requests to another DNS while using libc to resolve .local domains.

This software answers to DNS query by either forwarding the packet or by using the system-configured avahi.

## Why?

Because once again such nefarious and malevolent tool we refer to as __stampante__ (or *printer* for who is unfamiliar with the italian language) decided that .local domains can only be resolved using a DNS.
