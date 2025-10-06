<?php

/*
 *
__        __   _       _         _   _
 * \ \      / /__| |__   / \  _   _| |_| |__
 *  \ \ /\ / / _ \ '_ \ / _ \| | | | __| '_ \
 *   \ V  V /  __/ |_) / ___ \ |_| | |_| | | |
 *    \_/\_/ \___|_.__/_/   \_\__,_|\__|_| |_|
 *
 * This program is free software: you can redistribute and/or modify
 * it under the terms of the CSSM Unlimited License v2.0.
 *
 * This license permits unlimited use, modification, and distribution
 * for any purpose while maintaining authorship attribution.
 *
 * The software is provided "as is" without warranty of any kind.
 *
 * @author LuthMC
 * @author Sergiy Chernega
 * @link https://chernega.eu.org/
 *
 *
 */

declare(strict_types=1);

namespace ChernegaSergiy\WebAuth;

use Hebbinkpro\WebServer\http\message\HttpRequest;
use Hebbinkpro\WebServer\http\message\HttpResponse;
use Hebbinkpro\WebServer\http\server\HttpServerInfo;
use Hebbinkpro\WebServer\router\Router;
use Hebbinkpro\WebServer\WebServer;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\event\Listener;
use pocketmine\event\player\PlayerChatEvent;
use pocketmine\event\player\PlayerDropItemEvent;
use pocketmine\event\player\PlayerInteractEvent;
use pocketmine\event\player\PlayerJoinEvent;
use pocketmine\event\player\PlayerMoveEvent;
use pocketmine\event\player\PlayerQuitEvent;
use pocketmine\event\server\CommandEvent;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\Task;
use pocketmine\utils\Config;
use SQLite3;

class Main extends PluginBase implements Listener {

    private SQLite3 $db;
    private ?WebServer $webServer = null;
    private array $loggedInPlayers = [];
    private Config $config;

    public function onEnable(): void {
        if (!class_exists(WebServer::class)) {
            $this->getLogger()->critical("pmmp-webserver virion not found. Please install it to use this plugin.");
            $this->getServer()->getPluginManager()->disablePlugin($this);
            return;
        }

        $this->getServer()->getPluginManager()->registerEvents($this, $this);
        $this->saveDefaultConfig();
        $this->config = $this->getConfig();

        $dbPath = $this->getDataFolder() . "players.db";
        $this->db = new SQLite3($dbPath);
        $this->db->exec("CREATE TABLE IF NOT EXISTS players (username TEXT PRIMARY KEY, password TEXT);");
        $this->db->exec("CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, username TEXT, expires INTEGER);");

        // Cleanup expired sessions
        $this->getScheduler()->scheduleRepeatingTask(new class($this->db) extends Task {
            private SQLite3 $db;
            public function __construct(SQLite3 $db) { $this->db = $db; }
            public function onRun(): void {
                $this->db->exec("DELETE FROM web_sessions WHERE expires <= " . time());
            }
        }, 20 * 60 * 5); // Every 5 minutes

        $this->startWebServer($dbPath);
    }

    public function onDisable(): void {
        if ($this->webServer?->isStarted()) {
            $this->webServer->close();
        }
        $this->db->close();
    }

    public static function getCssStyles(): string {
        return '
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
                h1, h2 { color: #0056b3; }
                form { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
                input[type="text"], input[type="password"], input[type="submit"] {
                    width: 100%;
                    padding: 10px;
                    margin-bottom: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                input[type="submit"] {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    cursor: pointer;
                }
                input[type="submit"]:hover {
                    background-color: #0056b3;
                }
                p { margin-bottom: 10px; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .error { color: red; }
                .success { color: green; }

                /* Tabs styling */
                .tabs {
                    display: flex;
                    flex-wrap: wrap;
                    margin-bottom: 20px;
                }
                .tabs label {
                    order: 1;
                    display: block;
                    padding: 10px 20px;
                    margin-right: 2px;
                    cursor: pointer;
                    background: #e0e0e0;
                    font-weight: bold;
                    border-radius: 5px 5px 0 0;
                }
                .tabs .tab {
                    order: 99;
                    flex-grow: 1;
                    width: 100%;
                    display: none;
                    padding: 20px;
                    background: #fff;
                    border-radius: 0 8px 8px 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .tabs input[type="radio"] {
                    display: none;
                }
                .tabs input[type="radio"]:checked + label {
                    background: #007bff;
                    color: white;
                }
                .tabs input[type="radio"]:checked + label + .tab {
                    display: block;
                }
            </style>
        ';
    }

    private function startWebServer(string $dbPath): void {
        $router = new Router();

        $router->get("/login", function (HttpRequest $request, HttpResponse $response) {
            $error = $request->getURL()->getQueryParam("error");
            $html = '<!DOCTYPE html><html><head><title>Login</title>' . self::getCssStyles() . '</head><body>';
            $html .= '<h2>Login to your account</h2>';
            if ($error) {
                $html .= '<p style="color:red;">Invalid username or password.</p>';
            }
            $registered = $request->getURL()->getQueryParam("registered");
            if ($registered) {
                $html .= '<p style="color:green;">Registration successful! Please log in.</p>';
            }
            $deleteAccountSuccess = $request->getURL()->getQueryParam("delete_account_success");
            if ($deleteAccountSuccess) {
                $html .= '<p style="color:green;">Account deleted successfully!</p>';
            }
            $html .= '<form action="/login" method="post">';
            $html .= 'Username: <input type="text" name="username"><br>';
            $html .= 'Password: <input type="password" name="password"><br>';
            $html .= '<input type="submit" value="Login">';
            $html .= '</form>';
            $html .= '<p>Don\'t have an account? <a href="/register">Register here</a></p></body></html>';
            $response->send($html);
        });
        $router->get("/", static function (HttpRequest $request, HttpResponse $response) {
             $response->setStatus(301);
             $response->getHeaders()->setHeader("Location", "/login");
        });

        $router->post("/login", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            parse_str($request->getBody(), $body);
            $username = $body['username'] ?? '';
            $password = $body['password'] ?? '';

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT password FROM players WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            $db->close();

            if ($result && password_verify($password, $result['password'])) {
                $sessionToken = bin2hex(random_bytes(16));
                $expires = time() + 3600; // 1 hour

                $db = new SQLite3($dbPath);
                $stmt = $db->prepare("INSERT INTO web_sessions (token, username, expires) VALUES (:token, :user, :expires)");
                $stmt->bindValue(':token', $sessionToken);
                $stmt->bindValue(':user', $username);
                $stmt->bindValue(':expires', $expires);
                $stmt->execute();
                $db->close();

                $response->getHeaders()->setHeader("Set-Cookie", "session=$sessionToken; path=/; HttpOnly");
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/account");
            } else {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login?error=1");
            }
        }, $dbPath);

        $router->get("/register", function (HttpRequest $request, HttpResponse $response) {
            $error = $request->getURL()->getQueryParam("error");
            $html = '<!DOCTYPE html><html><head><title>Register</title>' . self::getCssStyles() . '</head><body>';
            $html .= '<h2>Register a new account</h2>';
            if ($error === "1") {
                $html .= '<p style="color:red;">Username already exists.</p>';
            } elseif ($error === "2") {
                $html .= '<p style="color:red;">Passwords do not match.</p>';
            } elseif ($error === "3") {
                $html .= '<p style="color:red;">Please fill in all fields.</p>';
            }
            $html .= '<form action="/register" method="post">';
            $html .= 'Username: <input type="text" name="username"><br>';
            $html .= 'Password: <input type="password" name="password"><br>';
            $html .= 'Confirm Password: <input type="password" name="confirm_password"><br>';
            $html .= '<input type="submit" value="Register">';
            $html .= '</form></body></html>';
            $response->send($html);
        });

        $router->post("/register", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            parse_str($request->getBody(), $body);
            $username = $body['username'] ?? '';
            $password = $body['password'] ?? '';
            $confirmPassword = $body['confirm_password'] ?? '';

            if (empty($username) || empty($password) || empty($confirmPassword)) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/register?error=3");
                return;
            }

            if ($password !== $confirmPassword) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/register?error=2");
                return;
            }

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT 1 FROM players WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $result = $stmt->execute()->fetchArray();

            if ($result) {
                $db->close();
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/register?error=1");
                return;
            }

            $passwordHash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $db->prepare("INSERT INTO players (username, password) VALUES (:user, :pass)");
            $stmt->bindValue(':user', $username);
            $stmt->bindValue(':pass', $passwordHash);
            $stmt->execute();
            $db->close();

            $response->setStatus(302);
            $response->getHeaders()->setHeader("Location", "/login?registered=1"); // Redirect to login with success message
        }, $dbPath);

        $router->get("/account", function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            $cookieHeader = $request->getHeaders()->getHeader("Cookie");
            $cookies = [];
            if ($cookieHeader !== null) {
                $parts = explode(';', $cookieHeader);
                foreach ($parts as $part) {
                    $pair = explode('=', $part, 2);
                    if (count($pair) === 2) {
                        $cookies[trim($pair[0])] = trim($pair[1]);
                    }
                }
            }
            $sessionToken = $cookies['session'] ?? null;

            if ($sessionToken === null) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login");
                return;
            }

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT username FROM web_sessions WHERE token = :token AND expires > :time");
            $stmt->bindValue(':token', $sessionToken);
            $stmt->bindValue(':time', time());
            $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            $db->close();

            if ($result) {
                $username = $result['username'];
                $html = '<!DOCTYPE html><html><head><title>Account</title>' . self::getCssStyles() . '</head><body>';
                $html .= "<h1>Welcome, " . htmlspecialchars($username) . "!</h1>";
                $html .= "<p>This is your account page.</p>";

                $html .= '<div class="tabs">';
                // Tab 1: Change Password
                $html .= '<input type="radio" name="tabs" id="tab1" checked>';
                $html .= '<label for="tab1">Change Password</label>';
                $html .= '<div class="tab">';
                $changePasswordError = $request->getURL()->getQueryParam("change_password_error");
                if ($changePasswordError === "1") {
                    $html .= '<p class="error">Current password incorrect.</p>';
                } elseif ($changePasswordError === "2") {
                    $html .= '<p class="error">New passwords do not match.</p>';
                } elseif ($changePasswordError === "3") {
                    $html .= '<p class="error">Please fill in all password fields.</p>';
                }
                $changePasswordSuccess = $request->getURL()->getQueryParam("change_password_success");
                if ($changePasswordSuccess) {
                    $html .= '<p class="success">Password changed successfully!</p>';
                }
                $html .= '<h2>Change Password</h2>';
                $html .= '<form action="/account/change-password" method="post">';
                $html .= 'Current Password: <input type="password" name="current_password"><br>';
                $html .= 'New Password: <input type="password" name="new_password"><br>';
                $html .= 'Confirm New Password: <input type="password" name="confirm_new_password"><br>';
                $html .= '<input type="submit" value="Change Password">';
                $html .= '</form>';
                $html .= '</div>'; // End tab1

                // Tab 2: Delete Account
                $html .= '<input type="radio" name="tabs" id="tab2">';
                $html .= '<label for="tab2">Delete Account</label>';
                $html .= '<div class="tab">';
                $deleteAccountError = $request->getURL()->getQueryParam("delete_account_error");
                if ($deleteAccountError === "1") {
                    $html .= '<p class="error">Current password incorrect.</p>';
                } elseif ($deleteAccountError === "2") {
                    $html .= '<p class="error">Please enter your password to confirm deletion.</p>';
                }
                $deleteAccountSuccess = $request->getURL()->getQueryParam("delete_account_success");
                if ($deleteAccountSuccess) {
                    $html .= '<p class="success">Account deleted successfully!</p>';
                }
                $html .= '<h2>Delete Account</h2>';
                $html .= '<p style="color:red;">WARNING: This action is irreversible. All your data will be lost.</p>';
                $html .= '<form action="/account/delete" method="post">';
                $html .= 'Enter your password to confirm: <input type="password" name="password_confirm"><br>';
                $html .= '<input type="submit" value="Delete Account">';
                $html .= '</form>';
                $html .= '</div>'; // End tab2
                $html .= '</div>'; // End tabs

                $html .= '<p><a href="/logout">Logout</a></p></body></html>';
                $response->send($html);
            } else {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login");
            }
        }, $dbPath);

        $router->post("/account/change-password", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            $cookieHeader = $request->getHeaders()->getHeader("Cookie");
            $cookies = [];
            if ($cookieHeader !== null) {
                $parts = explode(';', $cookieHeader);
                foreach ($parts as $part) {
                    $pair = explode('=', $part, 2);
                    if (count($pair) === 2) {
                        $cookies[trim($pair[0])] = trim($pair[1]);
                    }
                }
            }
            $sessionToken = $cookies['session'] ?? null;

            if ($sessionToken === null) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login");
                return;
            }

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT username FROM web_sessions WHERE token = :token AND expires > :time");
            $stmt->bindValue(':token', $sessionToken);
            $stmt->bindValue(':time', time());
            $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            $db->close();

            if (!$result) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login");
                return;
            }

            $username = $result['username'];

            parse_str($request->getBody(), $body);
            $currentPassword = $body['current_password'] ?? '';
            $newPassword = $body['new_password'] ?? '';
            $confirmNewPassword = $body['confirm_new_password'] ?? '';

            if (empty($currentPassword) || empty($newPassword) || empty($confirmNewPassword)) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/account?change_password_error=3");
                return;
            }

            if ($newPassword !== $confirmNewPassword) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/account?change_password_error=2");
                return;
            }

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT password FROM players WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

            if (!$result || !password_verify($currentPassword, $result['password'])) {
                $db->close();
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/account?change_password_error=1");
                return;
            }

            $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT);
            $stmt = $db->prepare("UPDATE players SET password = :pass WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $stmt->bindValue(':pass', $newPasswordHash);
            $stmt->execute();
            $db->close();

            $response->setStatus(302);
            $response->getHeaders()->setHeader("Location", "/account?change_password_success=1");
        }, $dbPath);

        $router->post("/account/delete", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            $cookieHeader = $request->getHeaders()->getHeader("Cookie");
            $cookies = [];
            if ($cookieHeader !== null) {
                $parts = explode(';', $cookieHeader);
                foreach ($parts as $part) {
                    $pair = explode('=', $part, 2);
                    if (count($pair) === 2) {
                        $cookies[trim($pair[0])] = trim($pair[1]);
                    }
                }
            }
            $sessionToken = $cookies['session'] ?? null;

            if ($sessionToken === null) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login");
                return;
            }

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT username FROM web_sessions WHERE token = :token AND expires > :time");
            $stmt->bindValue(':token', $sessionToken);
            $stmt->bindValue(':time', time());
            $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            $db->close();

            if (!$result) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/login");
                return;
            }

            $username = $result['username'];

            parse_str($request->getBody(), $body);
            $passwordConfirm = $body['password_confirm'] ?? '';

            if (empty($passwordConfirm)) {
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/account?delete_account_error=2");
                return;
            }

            $db = new SQLite3($dbPath);
            $stmt = $db->prepare("SELECT password FROM players WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

            if (!$result || !password_verify($passwordConfirm, $result['password'])) {
                $db->close();
                $response->setStatus(302);
                $response->getHeaders()->setHeader("Location", "/account?delete_account_error=1");
                return;
            }

            $stmt = $db->prepare("DELETE FROM players WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $stmt->execute();

            $stmt = $db->prepare("DELETE FROM web_sessions WHERE username = :user");
            $stmt->bindValue(':user', $username);
            $stmt->execute();
            $db->close();

            $response->getHeaders()->setHeader("Set-Cookie", "session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
            $response->setStatus(302);
            $response->getHeaders()->setHeader("Location", "/login?delete_account_success=1");
        }, $dbPath);

        $router->get("/logout", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            $cookieHeader = $request->getHeaders()->getHeader("Cookie");
            $cookies = [];
            if ($cookieHeader !== null) {
                $parts = explode(';', $cookieHeader);
                foreach ($parts as $part) {
                    $pair = explode('=', $part, 2);
                    if (count($pair) === 2) {
                        $cookies[trim($pair[0])] = trim($pair[1]);
                    }
                }
            }
            $sessionToken = $cookies['session'] ?? null;

            if ($sessionToken !== null) {
                $db = new SQLite3($dbPath);
                $stmt = $db->prepare("DELETE FROM web_sessions WHERE token = :token");
                $stmt->bindValue(':token', $sessionToken);
                $stmt->execute();
                $db->close();
            }

            $response->getHeaders()->setHeader("Set-Cookie", "session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
            $response->setStatus(302);
            $response->getHeaders()->setHeader("Location", "/login");
        }, $dbPath);

        $host = $this->config->get("host", "0.0.0.0");
        $port = (int)$this->config->get("port", 8080);

        $serverInfo = new HttpServerInfo($host, $port, $router);
        $this->webServer = new WebServer($this, $serverInfo);

        try {
            $this->webServer->start();
            $this->getLogger()->info("Web server started on $host:$port");
        } catch (\Exception $e) {
            $this->getLogger()->error("Failed to start web server: " . $e->getMessage());
        }
    }

    public function onCommand(CommandSender $sender, Command $command, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage("Please run this command in-game.");
            return false;
        }

        switch ($command->getName()) {
            case "register":
                if ($this->isRegistered($sender->getName())) {
                    $sender->sendMessage("§cYou are already registered.");
                    return false;
                }
                if (count($args) < 2) {
                    $sender->sendMessage("§cUsage: /register <password> <confirm_password>");
                    return false;
                }
                if ($args[0] !== $args[1]) {
                    $sender->sendMessage("§cPasswords do not match.");
                    return false;
                }

                $passwordHash = password_hash($args[0], PASSWORD_BCRYPT);
                $stmt = $this->db->prepare("INSERT INTO players (username, password) VALUES (:user, :pass)");
                $stmt->bindValue(":user", $sender->getName());
                $stmt->bindValue(":pass", $passwordHash);
                $stmt->execute();

                $this->loggedInPlayers[$sender->getName()] = true;
                $sender->sendMessage("§aYou have been successfully registered and logged in!");
                break;

            case "login":
                if (!$this->isRegistered($sender->getName())) {
                    $sender->sendMessage("§cYou are not registered. Use /register <password> <password>.");
                    return false;
                }
                if ($this->isLoggedIn($sender)) {
                    $sender->sendMessage("§cYou are already logged in.");
                    return false;
                }
                if (count($args) < 1) {
                    $sender->sendMessage("§cUsage: /login <password>");
                    return false;
                }

                $stmt = $this->db->prepare("SELECT password FROM players WHERE username = :user");
                $stmt->bindValue(":user", $sender->getName());
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if ($result && password_verify($args[0], $result['password'])) {
                    $this->loggedInPlayers[$sender->getName()] = true;
                    $sender->sendMessage("§aLogin successful!");
                } else {
                    $sender->sendMessage("§cIncorrect password.");
                }
                break;
        }
        return true;
    }

    public function isRegistered(string $playerName): bool {
        $stmt = $this->db->prepare("SELECT 1 FROM players WHERE username = :user");
        $stmt->bindValue(":user", $playerName);
        return $stmt->execute()->fetchArray() !== false;
    }

    public function isLoggedIn(Player $player): bool {
        return isset($this->loggedInPlayers[$player->getName()]);
    }

    public function onPlayerJoin(PlayerJoinEvent $event): void {
        $player = $event->getPlayer();
        if ($this->isRegistered($player->getName())) {
            $player->sendMessage("§aWelcome back! Please /login <password> to continue.");
        } else {
            $player->sendMessage("§aWelcome! Please /register <password> <password> to secure your account.");
        }
    }

    public function onPlayerQuit(PlayerQuitEvent $event): void {
        unset($this->loggedInPlayers[$event->getPlayer()->getName()]);
    }

    private function blockAction(Player $player, string $message, \pocketmine\event\Cancellable $event): void {
        if (!$this->isLoggedIn($player)) {
            $player->sendMessage($message);
            $event->cancel();
        }
    }

    public function onPlayerMove(PlayerMoveEvent $event): void {
        if (!$this->isLoggedIn($event->getPlayer())) {
            $event->cancel();
        }
    }

    public function onPlayerInteract(PlayerInteractEvent $event): void {
        $this->blockAction($event->getPlayer(), "§cPlease login or register to interact.", $event);
    }

    public function onPlayerDropItem(PlayerDropItemEvent $event): void {
        $this->blockAction($event->getPlayer(), "§cPlease login or register to drop items.", $event);
    }

    public function onPlayerChat(PlayerChatEvent $event): void {
        $this->blockAction($event->getPlayer(), "§cPlease login or register to chat.", $event);
    }

    public function onServerCommand(CommandEvent $event): void {
        $sender = $event->getSender();
        if (!$sender instanceof Player) return;

        $command = explode(" ", $event->getCommand())[0];

        if ($this->isLoggedIn($sender)) return;

        if (!in_array("/" . $command, ["/login", "/register"])){
            $sender->sendMessage("§cYou must login or register to use commands.");
            $event->cancel();
        }
    }
}
