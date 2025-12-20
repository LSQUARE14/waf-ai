<?php
include "includes/header.php";
include "includes/network.php";
?>

<h3>Ping Diagnostic</h3>

<form method="GET">
    Target host:
    <input type="text" name="host" placeholder="8.8.8.8">
    <button type="submit">Ping</button>
</form>

<?php
if (isset($_GET['host'])) {
    $result = ping_host($_GET['host']);
    echo "<pre>$result</pre>";
}
?>

<?php include "includes/footer.php"; ?>
