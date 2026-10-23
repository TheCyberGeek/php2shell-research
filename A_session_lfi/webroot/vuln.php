<?php
// LFI sink - stands in for any real include() with a user-influenced path
// (vulnerable plugins, theme loaders, custom routers, ...).
$page = $_GET['page'] ?? 'home';
include($page);
