<?php

function ping_host($host) {
    $cmd = "ping -c 1 " . $host;
    return shell_exec($cmd);
}
