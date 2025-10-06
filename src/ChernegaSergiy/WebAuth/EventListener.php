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
 * @author LuthMC
 * @author Sergiy Chernega
 * @link https://chernega.eu.org/
 *
 *
 */

declare(strict_types=1);

namespace ChernegaSergiy\WebAuth;

use pocketmine\event\Listener;
use pocketmine\event\player\PlayerChatEvent;
use pocketmine\event\player\PlayerDropItemEvent;
use pocketmine\event\player\PlayerInteractEvent;
use pocketmine\event\player\PlayerJoinEvent;
use pocketmine\event\player\PlayerMoveEvent;
use pocketmine\event\player\PlayerQuitEvent;
use pocketmine\event\server\CommandEvent;
use pocketmine\player\Player;

class EventListener implements Listener {

    private Main $plugin;

    public function __construct(Main $plugin) {
        $this->plugin = $plugin;
    }

    public function onPlayerJoin(PlayerJoinEvent $event): void {
        $player = $event->getPlayer();
        if ($this->plugin->isRegistered($player->getName())) {
            $player->sendMessage("§aWelcome back! Please /login <password> to continue.");
        } else {
            $player->sendMessage("§aWelcome! Please /register <password> <password> to secure your account.");
        }
    }

    public function onPlayerQuit(PlayerQuitEvent $event): void {
        $this->plugin->removeLoggedInPlayer($event->getPlayer()->getName());
    }


    public function onPlayerMove(PlayerMoveEvent $event): void {
        if (!$this->plugin->isLoggedIn($event->getPlayer())) {
            $event->cancel();
        }
    }

    public function onPlayerInteract(PlayerInteractEvent $event): void {
        if (!$this->plugin->isLoggedIn($event->getPlayer())) {
            $event->getPlayer()->sendMessage("§cPlease login or register to interact.");
            $event->cancel();
        }
    }

    public function onPlayerDropItem(PlayerDropItemEvent $event): void {
        if (!$this->plugin->isLoggedIn($event->getPlayer())) {
            $event->getPlayer()->sendMessage("§cPlease login or register to drop items.");
            $event->cancel();
        }
    }

    public function onPlayerChat(PlayerChatEvent $event): void {
        if (!$this->plugin->isLoggedIn($event->getPlayer())) {
            $event->getPlayer()->sendMessage("§cPlease login or register to chat.");
            $event->cancel();
        }
    }

    public function onServerCommand(CommandEvent $event): void {
        $sender = $event->getSender();
        if (!$sender instanceof Player) return;

        $command = explode(" ", $event->getCommand())[0];

        if ($this->plugin->isLoggedIn($sender)) return;

        if (!in_array("/" . $command, ["/login", "/register"])) {
            $sender->sendMessage("§cYou must login or register to use commands.");
            $event->cancel();
        }
    }
}
