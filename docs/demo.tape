# ttl — README demo cassette (live TUI traceroute, TUI-only frames)
#
# The launch (docker run, container start, first probe rounds) runs inside
# Hide, so the GIF opens on an already populated table and quits off-camera.
#
# Render from the repo root (needs vhs, ttyd, ffmpeg, docker):
#   cargo build --release
#   VHS_NO_SANDBOX=1 PATH="$HOME/.cache/rod/browser/chromium-1321438:$HOME/go/bin:$HOME/.local/bin:$PATH" vhs docs/demo.tape
#
# VHS 0.11 (go-rod 0.116) hangs opening its page on current Chrome, so it is
# pointed at rod's pinned Chromium 128 (picked up as `chrome` on PATH); fetch once:
#   curl -LO https://storage.googleapis.com/chromium-browser-snapshots/Linux_x64/1321438/chrome-linux.zip
#   unzip chrome-linux.zip && mv chrome-linux ~/.cache/rod/browser/chromium-1321438
# VHS_NO_SANDBOX is needed where unprivileged user namespaces are restricted
# (Ubuntu AppArmor).
#
# Raw-socket privilege comes from a throwaway Docker container
# (--cap-add=NET_RAW), so no host setcap/sudo; the fresh ./target/release/ttl
# is mounted in.

Output docs/demo.gif

Set Width 1280
Set Height 760
Set FontSize 15
Set Padding 16
Set Theme "Catppuccin Mocha"
Set CursorBlink false

# --- launch off-camera; Show only once hops, ASNs, rDNS and stats are in ------
Hide
Type "clear"
Enter
Sleep 300ms
Type "docker run --rm -it --cap-add=NET_RAW -v $PWD:/w -w /w ubuntu:24.04 ./target/release/ttl --no-update-check 1.1.1.1"
Enter
Sleep 15s
Show

# --- populated table ----------------------------------------------------------
Sleep 3s

# --- walk the selection down the path ------------------------------------------
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 700ms

# --- hop detail (percentiles, jitter, routing symmetry, TTL) -------------------
Enter
Sleep 5s
Escape
Sleep 1500ms

# --- brief help flash ------------------------------------------------------------
Type "?"
Sleep 2500ms
Escape
Sleep 3s          # hold on the full table (final good frame)

# --- quit off-camera so the last frame is the TUI, not the shell prompt --------
Hide
Type "q"
Sleep 1500ms
