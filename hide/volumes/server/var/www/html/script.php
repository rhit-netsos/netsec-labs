<?php
  $name = $_GET["name"];
  $output = shell_exec("/volumes/secret.bin '$name'");
  echo "<pre>$output</pre>";
?>
