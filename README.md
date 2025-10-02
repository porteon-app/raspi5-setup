Description of the setup of a new raspberry:
- run a new image from raspberry pi image for pi5_64x

You got it. Here’s a clean, repeatable way to get setup_adsb_v1-2.sh onto a fresh Pi 5 and run it.

First install the file setup_adsb_vn-n.sh
On the computer open a new shell and paste:
scp setup_adsb_v1-2.sh pi@lsgs.local:/home/pi/
[make sure you are connected with only one pi]

⸻

You’re hitting Permission denied (publickey) because you’re trying to copy as pi@ to /home/pi/, but this device is set up to use the lsgs user. There’s no matching key for pi, and password auth may be off—so the server rejects you before prompting.

Do this:

1) Use the correct user (and your key)

scp -i ~/.ssh/id_ed25519 setup_adsb_v1-2.sh lsgs@lsgs-02.local:~

Then on the Pi:

ssh -i ~/.ssh/id_ed25519 lsgs@lsgs-02.local
chmod +x ~/setup_adsb_v1-2.sh
sudo ~/setup_adsb_v1-2.sh

2) If .local doesn’t resolve, use the hotspot IP

scp -i ~/.ssh/id_ed25519 setup_adsb_v1-2.sh lsgs@172.20.10.X:~
ssh -i ~/.ssh/id_ed25519 lsgs@172.20.10.X

3) If you must use the pi account (not recommended here)

Enable/allow password auth (if permitted) and add your key:

ssh -o PubkeyAuthentication=no pi@lsgs-02.local    # login with the pi password
ssh-copy-id -i ~/.ssh/id_ed25519.pub pi@lsgs-02.local

…but since your services and paths are under /home/lsgs, stick with lsgs to keep everything consistent.

If it still denies, run a verbose attempt to see which key is offered:

ssh -vv lsgs@lsgs-02.local

and paste the last ~20 lines if you want me to pinpoint it.
