# How players reach the game servers

CrowsNest only starts and stops the game servers. Players connect to the game
itself, separately. Opening a port on your router is one option, but you don't
need one.

| Traffic | Notes |
|---|---|
| CrowsNest web UI | Plain HTTPS, so it works behind any reverse proxy or HTTP tunnel (e.g. a Cloudflare tunnel). |
| Game traffic (UDP) | **HTTP tunnels can't carry it.** Cloudflare tunnel public hostnames are HTTP(S) only, and Spectrum UDP proxying needs a paid plan. Use one of the paths below. |

## Per game

| Game | Join method without a router port | Notes |
|---|---|---|
| Palworld | Server's LAN address over a **private overlay network** (e.g. Tailscale) | Dedicated servers only join by IP:port. There's no built-in relay or Steam relay. |
| Valheim | **Crossplay join code** (start the server with `-crossplay`, PlayFab relay) | The code is in the server log and changes on every restart. Adds some relay latency. |
| Windrose | **Invite code** (the game's own P2P relay) | Set `INVITE_CODE` and `P2P_PROXY_ADDRESS` (host LAN IP), with `network_mode: host`. |

## Palworld over Tailscale

One way to set it up, with nothing installed on the host:

1. Run the `tailscale/tailscale` container as a subnet router for the host's
   LAN address. Give it its own bridge network, `NET_ADMIN` + `NET_RAW`,
   `/dev/net/tun`, and `net.ipv4.ip_forward=1`. Palworld's published
   `8211/udp` is then reachable through it, like from any LAN client.
2. Invite friends to the tailnet as **Members**. Use the access policy to give
   them only the game port on the server, e.g.
   `{"src": ["group:friends"], "dst": ["<server-lan-ip>/32"], "ip": ["udp:8211"]}`,
   and add policy `tests` that deny everything else, so a later edit can't
   widen it. The rest of your tailnet (subnet routes, exit node) stays usable
   by admins.
3. Set the game's `connect_address` to `<server-lan-ip>:8211`. The same
   address works on the LAN and over the tailnet.

Being on the tailnet gives friends no access to CrowsNest itself. They still
log in through however you publish the web UI.

To give friends another game over the overlay, add its port to their grant
(Valheim without crossplay: `udp:2456-2458`).

## Other options

- **Router port forward**: simplest, but exposes the game publicly.
- **Cloudflare Zero Trust + WARP client**: carries UDP to private IPs, but
  every player joins your Zero Trust org. The setup is heavier, and Palworld
  over it hasn't been tested.
- **Hosted UDP relay (e.g. playit.gg)**: nothing for players to install, but
  the server becomes public and only the game's server password guards it.
- **Steam**: no relay for these dedicated servers. Palworld's in-game co-op
  invite codes need the host playing on their own PC, so CrowsNest can't
  manage that.
