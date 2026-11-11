package com.jdj125.botpass.mixin;

import com.jdj125.botpass.BotPass;
import com.mojang.authlib.GameProfile;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.login.ServerboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * The only place BotPass touches Minecraft: when a bot name (and only a bot name) says hello on an online-mode server,
 * it skips the Mojang check here. The bot still has to prove the secret right after, in the configuration phase
 * (see {@link BotPass}), or it's kicked and its IP banned. Banned IPs are refused here before anything else.
 */
@Mixin(ServerLoginPacketListenerImpl.class)
public abstract class LoginMixin {
    @Shadow @Final MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow String requestedUsername;

    @Shadow
    abstract void startClientVerification(GameProfile profile);

    @Shadow
    public abstract void disconnect(Component reason);

    @Inject(method = "handleHello", at = @At("HEAD"), cancellable = true)
    private void botpass$hello(ServerboundHelloPacket packet, CallbackInfo ci) {
        String ip = BotPass.ip(connection.getRemoteAddress());
        if (BotPass.banned(ip)) {
            disconnect(Component.translatable("botpass.banned"));
            ci.cancel();
            return;
        }
        if (!server.usesAuthentication() || connection.isMemoryConnection() || !BotPass.isBotName(packet.name())) return;
        if (!BotPass.ipAllowed(ip)) {
            BotPass.fail(server, connection, packet.name(), ip, "ip");
            disconnect(Component.translatable("botpass.refused"));
            ci.cancel();
            return;
        }
        requestedUsername = packet.name();
        BotPass.pending(connection, packet.name());
        startClientVerification(UUIDUtil.createOfflineProfile(packet.name()));
        ci.cancel();
    }
}
