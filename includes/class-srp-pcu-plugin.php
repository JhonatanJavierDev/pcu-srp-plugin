<?php
class SRP_PCU_Plugin {
    private $db_host;
    private $db_user;
    private $db_password;
    private $db_name;
    private $pdo;

    // Constructor
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'settings_init'));
        add_shortcode('user_data', array($this, 'display_user_data'));
        add_shortcode('srp_pcu_login_form', array($this, 'render_login_form'));
        add_action('init', array($this, 'handle_login'));

        // Iniciar sesión aquí para evitar problemas con headers already sent
        session_start();
    }

    // Add admin menu
    public function add_admin_menu() {
        add_menu_page('SRP-PCU', 'SRP-PCU', 'manage_options', 'srp_pcu', array($this, 'options_page'), 'dashicons-admin-users');
    }

    // Initialize settings
    public function settings_init() {
        register_setting('pluginPage', 'srp_pcu_settings');

        add_settings_section(
            'srp_pcu_pluginPage_section',
            __('Database Configuration', 'srp-pcu'),
            array($this, 'settings_section_callback'),
            'pluginPage'
        );

        // Add fields for database configuration
        $this->add_settings_field('srp_pcu_db_host', __('Hostname', 'srp-pcu'), 'db_host_render');
        $this->add_settings_field('srp_pcu_db_user', __('Username', 'srp-pcu'), 'db_user_render');
        $this->add_settings_field('srp_pcu_db_password', __('Password', 'srp-pcu'), 'db_password_render');
        $this->add_settings_field('srp_pcu_db_name', __('Database Name', 'srp-pcu'), 'db_name_render');
    }

    // Helper function to add settings field
    private function add_settings_field($id, $label, $callback) {
        add_settings_field(
            $id,
            $label,
            array($this, $callback),
            'pluginPage',
            'srp_pcu_pluginPage_section'
        );
    }

    // Render database hostname field
    public function db_host_render() {
        $options = $this->get_plugin_options();
        ?>
        <input type='text' name='srp_pcu_settings[srp_pcu_db_host]' value='<?php echo $options['srp_pcu_db_host']; ?>'>
        <?php
    }

    // Render database username field
    public function db_user_render() {
        $options = $this->get_plugin_options();
        ?>
        <input type='text' name='srp_pcu_settings[srp_pcu_db_user]' value='<?php echo $options['srp_pcu_db_user']; ?>'>
        <?php
    }

    // Render database password field
    public function db_password_render() {
        $options = $this->get_plugin_options();
        ?>
        <input type='password' name='srp_pcu_settings[srp_pcu_db_password]' value='<?php echo $options['srp_pcu_db_password']; ?>'>
        <?php
    }

    // Render database name field
    public function db_name_render() {
        $options = $this->get_plugin_options();
        ?>
        <input type='text' name='srp_pcu_settings[srp_pcu_db_name]' value='<?php echo $options['srp_pcu_db_name']; ?>'>
        <?php
    }

    // Render database configuration section
    public function settings_section_callback() {
        echo __('Enter details of the external database.', 'srp-pcu');
    }

    // Render options page
    public function options_page() {
        ?>
        <form action='options.php' method='post'>
            <h2>SRP-PCU</h2>
            <?php
            settings_fields('pluginPage');
            do_settings_sections('pluginPage');
            submit_button();
            ?>
        </form>
        <?php
    }

    // Connect to external database
    private function connect_srp_db() {
        $options = $this->get_plugin_options();
        $this->db_host = $options['srp_pcu_db_host'];
        $this->db_user = $options['srp_pcu_db_user'];
        $this->db_password = $options['srp_pcu_db_password'];
        $this->db_name = $options['srp_pcu_db_name'];

        try {
            $this->pdo = new PDO("mysql:host=$this->db_host;dbname=$this->db_name", $this->db_user, $this->db_password);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die("Connection failed: " . $e->getMessage());
        }
    }

    // Render login form shortcode
    public function render_login_form() {
        if ($this->is_user_logged_in()) {
            return '<p>You are already logged in.</p>';
        }

        $form = '<form method="POST" action="' . esc_url($_SERVER['REQUEST_URI']) . '">
                    <label for="name">Username</label>
                    <input type="text" name="name" required>
                    
                    <label for="password">Password</label>
                    <input type="password" name="password" required>
                    
                    <input type="hidden" name="srp_pcu_login_nonce" value="' . $this->generate_nonce('srp_pcu_login') . '">
                    <button type="submit" name="srp_pcu_login_submit">Login</button>
                </form>';

        return $form;
    }

    private function log_message($message) {
        $log_file = plugin_dir_path(__FILE__) . 'srp-pcu.log';
        $timestamp = date('[Y-m-d H:i:s]');
        error_log("$timestamp $message\n", 3, $log_file);
    }

    // Handle login form submission
    public function handle_login() {
        if (isset($_POST['srp_pcu_login_submit'])) {
            if (!$this->verify_nonce('srp_pcu_login', $_POST['srp_pcu_login_nonce'])) {
                $this->log_message('Nonce verification failed');
                die('Nonce verification failed');
            }

            $name = sanitize_text_field($_POST['name']);
            $password = sanitize_text_field($_POST['password']);

            $login_result = $this->on_UserLogin($name, $password);

            if ($login_result['status'] === 'success') {
                // Start session for user
                session_start();
                $_SESSION['srp_pcu_user_id'] = $login_result['user_id'];

                wp_redirect(home_url());
                exit;
            } else {
                $this->log_message('Login failed: ' . $login_result['message']);
                add_action('the_content', function($content) use ($login_result) {
                    return '<p style="color:red;">' . $login_result['message'] . '</p>' . $content;
                });
            }
        }
    }

    // Generate nonce
    private function generate_nonce($action) {
        return md5($action . NONCE_SALT);
    }

    // Verify nonce
    private function verify_nonce($action, $nonce) {
        return $this->generate_nonce($action) === $nonce;
    }

    // Check if user is logged in
    public function is_user_logged_in() {
        session_start();
        return isset($_SESSION['srp_pcu_user_id']);
    }

    // Handle user login
    public function on_UserLogin($name, $password) {
        $this->connect_srp_db();

        $stmt = $this->pdo->prepare("SELECT * FROM player WHERE name = :name");
        $stmt->bindParam(':name', $name);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $hashed_password = hash('sha256', $password . $user['salt']);
            if ($hashed_password == $user['pass']) {
                return array('status' => 'success', 'message' => 'Login successful', 'user_id' => $user['id']);
            } else {
                return array('status' => 'error', 'message' => 'Incorrect password');
            }
        } else {
            return array('status' => 'error', 'message' => 'User not found');
        }
    }

    // Retrieve user data from database
    public function on_UserData() {
        session_start();
        if (isset($_SESSION['srp_pcu_user_id'])) {
            $this->connect_srp_db();
            $user_id = $_SESSION['srp_pcu_user_id'];

            $stmt = $this->pdo->prepare("SELECT * FROM player WHERE id = :id");
            $stmt->bindParam(':id', $user_id);
            $stmt->execute();
            $user_data = $stmt->fetch(PDO::FETCH_ASSOC);

            return $user_data;
        }
        return null;
    }

    // Get plugin options from database
    private function get_plugin_options() {
        return get_option('srp_pcu_settings', array());
    }

    // Display user data based on field
    public function display_user_data($atts) {
        if ($this->is_user_logged_in()) {
            $user_data = $this->on_UserData();
            if ($user_data) {
                $attribute = $atts['field'];
                return isset($user_data[$attribute]) ? $user_data[$attribute] : '';
            }
        }
        return '';
    }
}
