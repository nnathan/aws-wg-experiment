This is a terraform / opentofu setup to deploy a wireguard testbed.

```
[src] <-wg0:wg0-> [mid] <-wg1:wg0-> [snk]
```

(src,mid) on 172.16.100.0/24
(mid,snk) on 192.168.100.0/24

Once you've deployed, you can test end to end connectivity
by pinging 192.168.100.1 which will test `src <-> snk` traffic
that is fully sent through wireguard interfaces.

`psmall` and `pbig` in root directory are used as once off
custom packet generators, and should be run on `src`.
