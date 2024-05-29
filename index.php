<?php
/**
 * Plugin Name: SRP-PCU
 * Plugin URI: samp-info.vercel.app/downloads/wordpress-plugin/srp-pcu
 * Description: Este plugin te permite crear tu propia PCU del gamemode Super RolePlay de SA-MP usando Wordpress, permitiendo desde la autenticación del usuario hasta la obtención de estadísticas del jugador (próximamente, más datos como vehículos, etc.).
 * Version: 1.5
 * Author: Jhon Corella
 * Author URI: samp-info.vercel.app
 * License: GPL v2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: srp-pcu
 * Domain Path: /languages
 * 
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// Load the main plugin class
require_once plugin_dir_path(__FILE__) . 'includes/class-srp-pcu-plugin.php';

// Instantiate the plugin class
new SRP_PCU_Plugin();
