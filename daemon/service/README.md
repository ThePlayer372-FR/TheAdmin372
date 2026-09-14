- Create the sysadmin group ( `groupadd -r sysadmin` )
- Move this directory (daemon) in /opt/TheAdmin372/daemon
- Copy the file `theadmin372.service` in `/etc/systemd/system/theadmin372.service` ( `cp /opt/TheAdmin372/daemon/service/theadmin372.service /etc/systemd/system/theadmin372.service` )


# 1. Ricarica la configurazione di systemd
sudo systemctl daemon-reload

# 2. Abilita l'avvio automatico al boot e fallo partire adesso
sudo systemctl enable --now theadmin372.service

# 3. Controlla lo stato
sudo systemctl status theadmin372.service



# TEST

docker run --rm --name theadmin-container --privileged --cgroupns=host -e PYTHONDONTWRITEBYTECODE=1 -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v ".:/opt/TheAdmin372:ro" -v "theadmin_venv:/opt/TheAdmin372/daemon/.venv" theadmin-dev