Description of the setup of a new raspberry:
- run a new image from raspberry pi image for pi5_64x

# connect to the pi using the following command
ssh-keygen -R lsgs-02.local
ssh -i ~/.ssh/id_ed25519 lsgs@lsgs-02.local

# upload the setup_adsb.sh on the pi from the mac terminal
scp -i /.ssh/id_ed25519 adsb-edge-setup.sh lsgs@lsgs-02.local:

# upload the .env file
scp -i /.ssh/id_ed25519 adsb-edge.env lsgs@lsgs-02.local:

# next is move the .env to the right place
sudo mv ~/adsb-edge.env /etc/default/adsb-edge
sudo chmod 600 /etc/default/adsb-edge

# re-run the updated installer
chmod +x ~/adsb-edge-setup.sh
sudo ~/adsb-edge-setup.sh

# reboot the pi
sudo reboot

# restart all clearn
sudo systemctl daemon-reload
sudo systemctl reset-failed adsb-collector adsb-uploader || true
sudo systemctl enable --now dump1090-fa adsb-collector adsb-uploader
sudo systemctl enable --now adsb-health.timer net-failover.timer adsb-online-bootstrap.timer


# Tiny post-install checklist
systemctl status dump1090-fa adsb-collector adsb-uploader --no-pager
tail -n 50 ~/Documents/adsb/logs/collector.log ~/Documents/adsb/logs/uploader.log
aws s3 ls "<your S3 prefix>" --region "<region>" | tail


# Post-install edits:
sudo nano /etc/default/adsb-edge
Then: sudo systemctl daemon-reload && sudo systemctl restart adsb-collector adsb-uploader net-failover.timer adsb-health.timer


# if only Remoteit is available use:
ssh-keygen -R '[lsgs-01-ssh.at.remote.it]:33001'
ssh -l lsgs lsgs-01-ssh.at.remote.it -p 33001