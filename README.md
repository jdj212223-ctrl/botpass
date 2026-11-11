# BotPass 🎫🔐

A tiny NeoForge 1.21.1 mod that lets **one trusted bot** (default name `claude`) join an **online-mode** server without a Mojang account, while **everyone else** still logs in normally with their real account.

## How it stays safe
1. A bot name skips the Mojang check, and **only** a bot name does.
2. The server sends a random challenge. The bot answers with `HMAC-SHA256(secret, challenge)`. **The secret itself never travels over the network.**
3. A wrong answer, no answer within 15 s, a client without BotPass, or an IP or computer that isn't allowed means: **kicked**, the **IP is banned** (24 h by default), and **every op online gets an alert**.

## Setup
1. Put the BotPass jar on the **server** and on the **bot's** client. Normal players don't need it.
2. Start the server once. It makes `config/botpass/secret.txt` (readable only by its owner).
3. Copy that file to `config/botpass/secret.txt` in the **bot's** game folder. **Never share it.**
4. Optional, in `serverconfig/botpass-server.toml`: `botNames`, `allowedIps` (your bot's public IP), `allowedMachines` (an extra check; the secret is the real lock), `banMinutes`.

Be open with your players that the bot is a bot. MIT license.
