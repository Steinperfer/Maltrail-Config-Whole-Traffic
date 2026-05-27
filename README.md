# Maltrail-Config-Whole-Traffic
Maltrailconfig to get the whole traffic in your Ethernet!!!    
Only Works if you have a Fritzbox or another router with packetforwarding   
  
**1. got to your router**   
http://192.168.0.1/#/cap
"First Login, than change the URL and ad the /cap"
  
<img width="1420" height="804" alt="image" src="https://github.com/user-attachments/assets/3f4760d6-8eda-40b8-bebd-333fee92ab57" />

**2. Select start on Routing-Interface**  
accept the download and stop it after a view secconds,  

**3. Goto your browsers download site, and copy the download url**  
  
<img width="1223" height="366" alt="image" src="https://github.com/user-attachments/assets/e5b3b7a7-f6b5-4b33-8846-892130c81690" />
  
**4. Paste the download url in maltrail.service**
sudo nano /home/pi/maltrail/maltrail.conf

#############
```bash
cd /home/pi

git clone https://github.com/Steinperfer/Maltrail-Config-Whole-Traffic.git
cp /home/pi/Maltrail-Config-Whole-Traffic/pcap_fix_final.py /home/pi/
sudo cp /home/pi/Maltrail-Config-Whole-Traffic/maltrail.service /etc/systemd/system/
sudo cp /home/pi/Maltrail-Config-Whole-Traffic/get_sid.sh /usr/local/bin/


sudo rm -rf /home/pi/Maltrail-Config-Whole-Traffic
# change url and the path of your maltrail
sudo nano /etc/systemd/system/maltrail.service
#change password
sudo nano /usr/local/bin/get_sid.sh


# Systemd
sudo systemctl daemon-reload
sudo systemctl start maltrail.service
sudo systemctl enable maltrail.service

sudo systemctl status maltrail.service
```
  
Delete logs older than 1 month:
```
sudo nano /etc/logrotate.d/maltrail
```
  
insert
```
/var/log/maltrail/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 root root
    dateext
    dateformat -%Y%m%d
}
```
  
restart  
```
systemctl status logrotate.timer
sudo systemctl restart maltrail

```
