<?php

/*
 *
 * __        __   _       _         _   _
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
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\Task;
use pocketmine\utils\Config;
use SQLite3;

class Main extends PluginBase {

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

        $this->getServer()->getPluginManager()->registerEvents(new EventListener($this), $this);
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

    private function startWebServer(string $dbPath): void {
        $router = new Router();

        $router->get("/login", function (HttpRequest $request, HttpResponse $response) {
            $error = $request->getURL()->getQueryParam("error");
            $html = '<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Login</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head>
            <body>
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center mb-4">Login to your account</h2>';
            if ($error) {
                $html .= '<div class="alert alert-danger" role="alert">Invalid username or password.</div>';
            }
            $registered = $request->getURL()->getQueryParam("registered");
            if ($registered) {
                $html .= '<div class="alert alert-success" role="alert">Registration successful! Please log in.</div>';
            }
            $deleteAccountSuccess = $request->getURL()->getQueryParam("delete_account_success");
            if ($deleteAccountSuccess) {
                $html .= '<div class="alert alert-success" role="alert">Account deleted successfully!</div>';
            }
            $html .= '                                    <form action="/login" method="post">
                                        <div class="mb-3">
                                            <label for="username" class="form-label">Username:</label>
                                            <input type="text" class="form-control" id="username" name="username" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="password" class="form-label">Password:</label>
                                            <input type="password" class="form-control" id="password" name="password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Login</button>
                                    </form>
                                    <p class="text-center mt-3">Don\'t have an account? <a href="/register">Register here</a></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
            </body>
            </html>';
            $response->send($html);
        });
        $router->get("/", static function (HttpRequest $request, HttpResponse $response) {
             $response->setStatus(301);
             $response->getHeaders()->setHeader("Location", "/login");
        });

        $router->post("/login", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            parse_str($request->getBody(), $body);
            $username = strtolower($body['username'] ?? '');
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
            $html = '<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Register</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head>
            <body>
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center mb-4">Register a new account</h2>';
            if ($error === "1") {
                $html .= '<div class="alert alert-danger" role="alert">Username already exists.</div>';
            } elseif ($error === "2") {
                $html .= '<div class="alert alert-danger" role="alert">Passwords do not match.</div>';
            } elseif ($error === "3") {
                $html .= '<div class="alert alert-danger" role="alert">Please fill in all fields.</div>';
            }
            $html .= '                                    <form action="/register" method="post">
                                        <div class="mb-3">
                                            <label for="username" class="form-label">Username:</label>
                                            <input type="text" class="form-control" id="username" name="username" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="password" class="form-label">Password:</label>
                                            <input type="password" class="form-control" id="password" name="password" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="confirm_password" class="form-label">Confirm Password:</label>
                                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Register</button>
                                    </form>
                                    <p class="text-center mt-3">Already have an account? <a href="/login">Login here</a></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
            </body>
            </html>';
            $response->send($html);
        });

        $router->post("/register", static function (HttpRequest $request, HttpResponse $response, string $dbPath) {
            parse_str($request->getBody(), $body);
            $username = strtolower($body['username'] ?? '');
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
                $username = strtolower($result['username']);
                $html = '<!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Account</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
                </head>
                <body>
                    <div class="container mt-5">
                        <h1 class="mb-4">Welcome, ' . htmlspecialchars($username) . '!</h1>
                        <p>This is your account page.</p>

                        <ul class="nav nav-tabs" id="myTab" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" id="change-password-tab" data-bs-toggle="tab" data-bs-target="#change-password" type="button" role="tab" aria-controls="change-password" aria-selected="true">Change Password</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="delete-account-tab" data-bs-toggle="tab" data-bs-target="#delete-account" type="button" role="tab" aria-controls="delete-account" aria-selected="false">Delete Account</button>
                            </li>
                        </ul>
                        <div class="tab-content" id="myTabContent">
                            <div class="tab-pane fade show active" id="change-password" role="tabpanel" aria-labelledby="change-password-tab">
                                <div class="card mt-3">
                                    <div class="card-body">
                                        <h2 class="card-title">Change Password</h2>';
                $changePasswordError = $request->getURL()->getQueryParam("change_password_error");
                if ($changePasswordError === "1") {
                    $html .= '<div class="alert alert-danger" role="alert">Current password incorrect.</div>';
                } elseif ($changePasswordError === "2") {
                    $html .= '<div class="alert alert-danger" role="alert">New passwords do not match.</div>';
                } elseif ($changePasswordError === "3") {
                    $html .= '<div class="alert alert-danger" role="alert">Please fill in all password fields.</div>';
                }
                $changePasswordSuccess = $request->getURL()->getQueryParam("change_password_success");
                if ($changePasswordSuccess) {
                    $html .= '<div class="alert alert-success" role="alert">Password changed successfully!</div>';
                }
                $html .= '                                        <form action="/account/change-password" method="post">
                                            <div class="mb-3">
                                                <label for="current_password" class="form-label">Current Password:</label>
                                                <input type="password" class="form-control" id="current_password" name="current_password" required>
                                            </div>
                                            <div class="mb-3">
                                                <label for="new_password" class="form-label">New Password:</label>
                                                <input type="password" class="form-control" id="new_password" name="new_password" required>
                                            </div>
                                            <div class="mb-3">
                                                <label for="confirm_new_password" class="form-label">Confirm New Password:</label>
                                                <input type="password" class="form-control" id="confirm_new_password" name="confirm_new_password" required>
                                            </div>
                                            <button type="submit" class="btn btn-primary">Change Password</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane fade" id="delete-account" role="tabpanel" aria-labelledby="delete-account-tab">
                                <div class="card mt-3">
                                    <div class="card-body">
                                        <h2 class="card-title">Delete Account</h2>
                                        <p class="text-danger">WARNING: This action is irreversible. All your data will be lost.</p>';
                $deleteAccountError = $request->getURL()->getQueryParam("delete_account_error");
                if ($deleteAccountError === "1") {
                    $html .= '<div class="alert alert-danger" role="alert">Current password incorrect.</div>';
                } elseif ($deleteAccountError === "2") {
                    $html .= '<div class="alert alert-danger" role="alert">Please enter your password to confirm deletion.</div>';
                }
                $deleteAccountSuccess = $request->getURL()->getQueryParam("delete_account_success");
                if ($deleteAccountSuccess) {
                    $html .= '<div class="alert alert-success" role="alert">Account deleted successfully!</div>';
                }
                $html .= '                                        <form action="/account/delete" method="post">
                                            <div class="mb-3">
                                                <label for="password_confirm" class="form-label">Enter your password to confirm:</label>
                                                <input type="password" class="form-control" id="password_confirm" name="password_confirm" required>
                                            </div>
                                            <button type="submit" class="btn btn-danger">Delete Account</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <p class="mt-4"><a href="/logout" class="btn btn-secondary">Logout</a></p>
                    </div>
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
                </body>
                </html>';
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

            $username = strtolower($result['username']);

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

            $username = strtolower($result['username']);

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
                $playerName = strtolower($sender->getName());
                if ($this->isRegistered($playerName)) {
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
                $stmt->bindValue(":user", $playerName);
                $stmt->bindValue(":pass", $passwordHash);
                $stmt->execute();

                $this->loggedInPlayers[$playerName] = true;
                $sender->sendMessage("§aYou have been successfully registered and logged in!");
                break;

            case "login":
                $playerName = strtolower($sender->getName());
                if (!$this->isRegistered($playerName)) {
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
                $stmt->bindValue(":user", $playerName);
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if ($result && password_verify($args[0], $result['password'])) {
                    $this->loggedInPlayers[$playerName] = true;
                    $sender->sendMessage("§aLogin successful!");
                } else {
                    $sender->sendMessage("§cIncorrect password.");
                }
                break;
        }
        return true;
    }

    public function isRegistered(string $playerName): bool {
        $playerName = strtolower($playerName);
        $stmt = $this->db->prepare("SELECT 1 FROM players WHERE username = :user");
        $stmt->bindValue(":user", $playerName);
        return $stmt->execute()->fetchArray() !== false;
    }

    public function isLoggedIn(Player $player): bool {
        return isset($this->loggedInPlayers[strtolower($player->getName())]);
    }

    public function removeLoggedInPlayer(string $playerName): void {
        $playerName = strtolower($playerName);
        unset($this->loggedInPlayers[$playerName]);
    }
}
