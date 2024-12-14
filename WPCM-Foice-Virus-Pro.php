<?php
/*
Plugin Name: WPCM Foice Virus Pro
Description: Plugin profissional para detectar e remover vírus e malwares em uma instalação WordPress, com whitelist, backup, segurança aprimorada e recursos avançados.
Version: 2.2
Author: Ninja Code
*/

if (!defined('ABSPATH')) {
    exit; // Evita acesso direto.
}

// Diretório para backups
define('WPCM_BACKUP_DIR', WP_CONTENT_DIR . '/wpcm-backups/');

// Classe principal do plugin
class WPCM_Foice_Virus_Pro {
    private $scanner;
    private $backup;
    private $security;
    private $settings;

    public function __construct() {
        $this->settings = new WPCM_Settings();
        $this->scanner = new WPCM_Scanner($this->settings);
        $this->backup = new WPCM_Backup($this->settings);
        $this->security = new WPCM_Security($this->settings);

        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('wp_ajax_wpcm_foice_virus_pro_scan', [$this, 'handle_scan_request']);
        add_action('wp_ajax_wpcm_foice_virus_pro_clean', [$this, 'handle_clean_request']);
        add_action('wp_ajax_wpcm_foice_virus_pro_restore', [$this, 'handle_restore_request']);
        add_action('wp_ajax_wpcm_foice_virus_pro_delete_backup', [$this, 'handle_delete_backup_request']);
        add_action('admin_init', [$this, 'handle_settings_update']);
    }

    public function add_admin_menu() {
        add_menu_page(
            'WPCM Foice Virus Pro',
            'Foice Virus Pro',
            'manage_options',
            'wpcm-foice-virus-pro',
            [$this, 'render_dashboard_page'],
            'dashicons-shield'
        );

        add_submenu_page(
            'wpcm-foice-virus-pro',
            'Configurações',
            'Configurações',
            'manage_options',
            'wpcm-foice-virus-pro-settings',
            [$this, 'render_settings_page']
        );

        add_submenu_page(
            'wpcm-foice-virus-pro',
            'Logs',
            'Logs',
            'manage_options',
            'wpcm-foice-virus-pro-logs',
            [$this, 'render_logs_page']
        );
    }

    public function enqueue_scripts($hook) {
        if ($hook === 'toplevel_page_wpcm-foice-virus-pro' || $hook === 'foice-virus-pro_page_wpcm-foice-virus-pro-settings' || $hook === 'foice-virus-pro_page_wpcm-foice-virus-pro-logs') {
            wp_enqueue_style('wpcm-foice-virus-pro-style', plugin_dir_url(__FILE__) . 'assets/css/style.css', [], '2.2');
            wp_enqueue_script('wpcm-foice-virus-pro-script', plugin_dir_url(__FILE__) . 'assets/js/script.js', ['jquery'], '2.2', true);
            wp_localize_script('wpcm-foice-virus-pro-script', 'wpcm_foice_virus_pro_ajax', [
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('wpcm_foice_virus_pro_nonce'),
            ]);
        }
    }

    public function render_dashboard_page() {
        ?>
        <div class="wrap">
            <h1>WPCM Foice Virus Pro - Painel</h1>
            
            <div class="wpcm-section">
                <h2>Varredura de Arquivos</h2>
                <p>Clique no botão abaixo para iniciar uma varredura em busca de vírus e malwares nos arquivos do seu site WordPress.</p>
                <button id="wpcm-scan-button" class="button button-primary">Iniciar Varredura</button>
                <div id="wpcm-scan-results"></div>
            </div>
            
            <div class="wpcm-section">
                <h2>Arquivos de Backup</h2>
                <p>Lista de arquivos de backup criados durante a limpeza de arquivos suspeitos.</p>
                <table id="wpcm-backup-table" class="widefat">
                    <thead>
                        <tr>
                            <th>Arquivo</th>
                            <th>Data de Criação</th>
                            <th>Ações</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $backups = $this->backup->get_backup_files();
                        foreach ($backups as $backup) {
                            $file_name = basename($backup);
                            $file_date = date('Y-m-d H:i:s', filemtime($backup));
                            ?>
                            <tr>
                                <td><?php echo esc_html($file_name); ?></td>
                                <td><?php echo esc_html($file_date); ?></td>
                                <td>
                                    <button class="button button-secondary wpcm-restore-backup" data-backup="<?php echo esc_attr($backup); ?>">Restaurar</button>
                                    <button class="button button-secondary wpcm-delete-backup" data-backup="<?php echo esc_attr($backup); ?>">Excluir</button>
                                </td>
                            </tr>
                            <?php
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    public function render_settings_page() {
        ?>
        <div class="wrap">
            <h1>WPCM Foice Virus Pro - Configurações</h1>
            
            <form method="post" action="<?php echo admin_url('admin-post.php'); ?>">
                <?php wp_nonce_field('wpcm_foice_virus_pro_settings_nonce', 'wpcm_foice_virus_pro_settings_nonce'); ?>
                <input type="hidden" name="action" value="wpcm_foice_virus_pro_settings_update">
                
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="whitelist">Lista de Permissões (Whitelist)</label></th>
                        <td>
                            <textarea name="wpcm_foice_virus_pro_settings[whitelist]" id="whitelist" rows="5" cols="50"><?php echo esc_textarea($this->settings->get_option('whitelist')); ?></textarea>
                            <p class="description">Insira um arquivo por linha. Esses arquivos serão excluídos da varredura.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="suspicious_patterns">Padrões Suspeitos</label></th>
                        <td>
                            <textarea name="wpcm_foice_virus_pro_settings[suspicious_patterns]" id="suspicious_patterns" rows="5" cols="50"><?php echo esc_textarea($this->settings->get_option('suspicious_patterns')); ?></textarea>
                            <p class="description">Insira um padrão (expressão regular) por linha. Esses padrões serão usados para identificar código suspeito durante a varredura.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="enable_request_blocking">Bloqueio de Requisições Suspeitas</label></th>
                        <td>
                            <input type="checkbox" name="wpcm_foice_virus_pro_settings[enable_request_blocking]" id="enable_request_blocking" value="1" <?php checked($this->settings->get_option('enable_request_blocking'), 1); ?>>
                            <label for="enable_request_blocking">Ativar bloqueio de requisições suspeitas</label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="email_notifications">Notificações por Email</label></th>
                        <td>
                            <input type="checkbox" name="wpcm_foice_virus_pro_settings[email_notifications]" id="email_notifications" value="1" <?php checked($this->settings->get_option('email_notifications'), 1); ?>>
                            <label for="email_notifications">Ativar notificações por email</label>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    public function render_logs_page() {
        ?>
        <div class="wrap">
            <h1>WPCM Foice Virus Pro - Logs</h1>
            
            <div class="wpcm-section">
                <h2>Logs de Varredura</h2>
                <textarea rows="20" cols="100" readonly><?php echo esc_textarea(file_get_contents(WPCM_BACKUP_DIR . 'scan_log.txt')); ?></textarea>
            </div>
        </div>
        <?php
    }

    public function handle_scan_request() {
        check_ajax_referer('wpcm_foice_virus_pro_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permissão negada.');
        }

        $suspected_files = $this->scanner->scan_directory(ABSPATH . 'wp-content');

        // Log de varredura
        file_put_contents(WPCM_BACKUP_DIR . 'scan_log.txt', implode("\n", $suspected_files));

        // Notificação por email
        if ($this->settings->get_option('email_notifications')) {
            $to = get_option('admin_email');
            $subject = 'WPCM Foice Virus Pro - Varredura Concluída';
            $message = 'A varredura foi concluída. Arquivos suspeitos encontrados: ' . implode("\n", $suspected_files);
            wp_mail($to, $subject, $message);
        }

        wp_send_json_success($suspected_files);
    }

    public function handle_clean_request() {
        check_ajax_referer('wpcm_foice_virus_pro_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permissão negada.');
        }

        $files_to_clean = isset($_POST['files']) ? array_map('sanitize_text_field', $_POST['files']) : [];

        if (empty($files_to_clean)) {
            wp_send_json_error('Nenhum arquivo selecionado para limpeza.');
        }

        $cleaned_files = [];

        foreach ($files_to_clean as $file) {
            $file_path = realpath(ABSPATH . wp_normalize_path($file));

            if (false !== $file_path && $this->scanner->is_file_suspicious($file_path)) {
                $this->backup->backup_file($file_path);
                $this->scanner->clean_file($file_path);
                $cleaned_files[] = $file;
            }
        }

        // Notificação por email
        if ($this->settings->get_option('email_notifications')) {
            $to = get_option('admin_email');
            $subject = 'WPCM Foice Virus Pro - Limpeza Concluída';
            $message = 'A limpeza foi concluída. Arquivos limpos: ' . implode("\n", $cleaned_files);
            wp_mail($to, $subject, $message);
        }

        wp_send_json_success($cleaned_files);
    }

    public function handle_restore_request() {
        check_ajax_referer('wpcm_foice_virus_pro_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permissão negada.');
        }

        $backup_file = isset($_POST['backup_file']) ? sanitize_text_field($_POST['backup_file']) : '';

        if (empty($backup_file)) {
            wp_send_json_error('Nenhum arquivo de backup selecionado para restauração.');
        }

        $original_file = isset($_POST['original_file']) ? sanitize_text_field($_POST['original_file']) : '';

        if (empty($original_file)) {
            wp_send_json_error('Nenhum arquivo original especificado para restauração.');
        }

        $this->backup->restore_file($backup_file, ABSPATH . wp_normalize_path($original_file));

        // Notificação por email
        if ($this->settings->get_option('email_notifications')) {
            $to = get_option('admin_email');
            $subject = 'WPCM Foice Virus Pro - Restauração Concluída';
            $message = 'A restauração foi concluída. Arquivo restaurado: ' . $original_file;
            wp_mail($to, $subject, $message);
        }

        wp_send_json_success();
    }

    public function handle_delete_backup_request() {
        check_ajax_referer('wpcm_foice_virus_pro_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permissão negada.');
        }

        $backup_file = isset($_POST['backup_file']) ? sanitize_text_field($_POST['backup_file']) : '';

        if (empty($backup_file)) {
            wp_send_json_error('Nenhum arquivo de backup selecionado para exclusão.');
        }

        $this->backup->delete_backup($backup_file);

        wp_send_json_success();
    }

    public function handle_settings_update() {
        if (isset($_POST['wpcm_foice_virus_pro_settings'])) {
            check_admin_referer('wpcm_foice_virus_pro_settings_nonce', 'wpcm_foice_virus_pro_settings_nonce');

            if (!current_user_can('manage_options')) {
                wp_die('Permissão negada.');
            }

            $settings = isset($_POST['wpcm_foice_virus_pro_settings']) ? (array) $_POST['wpcm_foice_virus_pro_settings'] : [];
            $sanitized_settings = [];

            foreach ($settings as $key => $value) {
                $sanitized_settings[$key] = sanitize_text_field($value);
            }

            $this->settings->update_settings($sanitized_settings);

            wp_safe_redirect(admin_url('admin.php?page=wpcm-foice-virus-pro-settings&updated=true'));
            exit;
        }
    }
}

// Classe de configurações do plugin
class WPCM_Settings {
    private $options;

    public function __construct() {
        $this->options = get_option('wpcm_foice_virus_pro_settings', []);
    }

    public function get_option($key, $default = '') {
        return isset($this->options[$key]) ? $this->options[$key] : $default;
    }

    public function update_settings($settings) {
        $this->options = array_merge($this->options, $settings);
        update_option('wpcm_foice_virus_pro_settings', $this->options);
    }
}

// Classe de varredura de arquivos
class WPCM_Scanner {
    private $settings;
    private $whitelist;
    private $suspicious_patterns;

    public function __construct($settings) {
        $this->settings = $settings;
        $this->whitelist = $this->get_whitelist();
        $this->suspicious_patterns = $this->get_suspicious_patterns();
    }

    private function get_whitelist() {
        $default_whitelist = [
            ABSPATH . 'wp-config.php',
            ABSPATH . 'wp-settings.php',
            ABSPATH . 'wp-load.php',
            ABSPATH . 'wp-blog-header.php',
            ABSPATH . 'wp-cron.php',
            ABSPATH . 'wp-mail.php',
            ABSPATH . 'wp-activate.php',
            ABSPATH . 'wp-signup.php',
            ABSPATH . 'wp-comments-post.php',
            ABSPATH . 'wp-links-opml.php',
            ABSPATH . 'wp-trackback.php',
            ABSPATH . 'xmlrpc.php',
            ABSPATH . 'wp-admin/admin.php',
            ABSPATH . 'wp-admin/admin-ajax.php',
            ABSPATH . 'wp-admin/load-scripts.php',
            ABSPATH . 'wp-admin/load-styles.php',
            ABSPATH . 'wp-admin/upgrade.php',
            ABSPATH . 'wp-admin/install.php',
            ABSPATH . 'wp-admin/plugins.php',
            ABSPATH . 'wp-admin/themes.php',
        ];

        $custom_whitelist = explode("\n", $this->settings->get_option('whitelist', ''));
        $custom_whitelist = array_map('trim', $custom_whitelist);
        $custom_whitelist = array_filter($custom_whitelist);

        return array_merge($default_whitelist, $custom_whitelist);
    }

    private function get_suspicious_patterns() {
        $default_patterns = [
            '/base64_decode/i',
            '/eval\s*\(/i',
            '/assert\s*\(/i',
            '/system\s*\(/i',
            '/shell_exec\s*\(/i',
            '/passthru\s*\(/i',
            '/exec\s*\(/i',
            '/proc_open\s*\(/i',
            '/popen\s*\(/i',
            '/curl_exec\s*\(/i',
            '/curl_multi_exec\s*\(/i',
            '/parse_ini_file\s*\(/i',
            '/show_source\s*\(/i',
            '/file_get_contents\s*\(/i',
            '/file_put_contents\s*\(/i',
            '/fopen\s*\(/i',
            '/fwrite\s*\(/i',
            '/unlink\s*\(/i',
        ];

        $custom_patterns = explode("\n", $this->settings->get_option('suspicious_patterns', ''));
        $custom_patterns = array_map('trim', $custom_patterns);
        $custom_patterns = array_filter($custom_patterns);

        return array_merge($default_patterns, $custom_patterns);
    }

    public function scan_directory($dir) {
        $suspected_files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));

        foreach ($iterator as $file) {
            if ($file->isFile() && !$this->is_file_whitelisted($file->getPathname())) {
                if ($this->is_file_suspicious($file->getPathname())) {
                    $suspected_files[] = $file->getPathname();
                }
            }
        }

        return $suspected_files;
    }

    public function is_file_whitelisted($file) {
        return in_array($file, $this->whitelist);
    }

    public function is_file_suspicious($file) {
        $content = file_get_contents($file);

        foreach ($this->suspicious_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    public function clean_file($file) {
        if (is_writable($file)) {
            file_put_contents($file, '');
        }
    }
}

// Classe de backup de arquivos
class WPCM_Backup {
    private $settings;

    public function __construct($settings) {
        $this->settings = $settings;
    }

    public function backup_file($file) {
        if (!is_dir(WPCM_BACKUP_DIR)) {
            mkdir(WPCM_BACKUP_DIR, 0755, true);
        }

        $backup_file = WPCM_BACKUP_DIR . basename($file) . '_' . time() . '_' . wp_hash($file) . '.zip';
        $zip = new ZipArchive();

        if ($zip->open($backup_file, ZipArchive::CREATE) === true) {
            $zip->addFile($file, basename($file));
            $zip->close();
        }
    }

    public function get_backup_files() {
        $backup_files = [];

        if (is_dir(WPCM_BACKUP_DIR)) {
            $files = scandir(WPCM_BACKUP_DIR);

            foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                    $backup_files[] = WPCM_BACKUP_DIR . $file;
                }
            }
        }

        return $backup_files;
    }

    public function restore_file($backup_file, $original_file) {
        if (is_file($backup_file)) {
            $zip = new ZipArchive();
            if ($zip->open($backup_file) === true) {
                $zip->extractTo(dirname($original_file));
                $zip->close();
            }
        }
    }

    public function delete_backup($backup_file) {
        if (is_file($backup_file)) {
            unlink($backup_file);
        }
    }
}

// Classe de recursos de segurança
class WPCM_Security {
    private $settings;

    public function __construct($settings) {
        $this->settings = $settings;
        add_action('init', [$this, 'block_suspicious_requests']);
    }

    public function block_suspicious_requests() {
        if ($this->settings->get_option('enable_request_blocking', false)) {
            // Bloqueio de requisições suspeitas com base em critérios específicos
            $suspicious_user_agents = [
                'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
            ];

            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

            if (in_array($user_agent, $suspicious_user_agents)) {
                wp_die('Acesso negado. Agente de usuário suspeito detectado.', 'Acesso Negado', ['response' => 403]);
            }
        }
    }
}

// Tratamento de erros e logging
function wpcm_foice_virus_pro_error_handler($errno, $errstr, $errfile, $errline) {
    error_log("[WPCM Foice Virus Pro] Erro: $errstr. Arquivo: $errfile. Linha: $errline", 3, WPCM_BACKUP_DIR . 'error.log');
}

set_error_handler('wpcm_foice_virus_pro_error_handler');

// Internacionalização
function wpcm_foice_virus_pro_load_textdomain() {
    load_plugin_textdomain('wpcm-foice-virus-pro', false, dirname(plugin_basename(__FILE__)) . '/languages/');
}

add_action('plugins_loaded', 'wpcm_foice_virus_pro_load_textdomain');

// Estilos e scripts
function wpcm_foice_virus_pro_enqueue_assets() {
    wp_enqueue_style('wpcm-foice-virus-pro-style', plugin_dir_url(__FILE__) . 'assets/css/style.css', [], '2.2');
    wp_enqueue_script('wpcm-foice-virus-pro-script', plugin_dir_url(__FILE__) . 'assets/js/script.js', ['jquery'], '2.2', true);
    wp_localize_script('wpcm-foice-virus-pro-script', 'wpcm_foice_virus_pro_ajax', [
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('wpcm_foice_virus_pro_nonce'),
    ]);
}

add_action('admin_enqueue_scripts', 'wpcm_foice_virus_pro_enqueue_assets');

// Inicializa o plugin
new WPCM_Foice_Virus_Pro();
