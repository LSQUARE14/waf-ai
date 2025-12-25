<?php

function ping_host($host) {
    $cmd = "ping -c 4 " . $host;
    return shell_exec($cmd);
}
