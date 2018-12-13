function FindProxyForURL(url, host) {
    // our local URLs from the domains below example.com don't need a proxy:
    // if (shexpmatch(host, "http://*"))
    // {
    //     return "direct";
    // }

    // URLs within this network are accessed through
    // port 8080 on fastproxy.example.com:


    // All other requests go through port 8080 of proxy.example.com.
    // should that fail to respond, go directly to the WWW:
    return "SOCKS5 127.0.0.1:1080";
}
