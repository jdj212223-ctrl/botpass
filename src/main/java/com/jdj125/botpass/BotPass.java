package com.jdj125.botpass;

import com.mojang.logging.LogUtils;
import io.netty.buffer.ByteBuf;
import net.minecraft.ChatFormatting;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.loading.FMLPaths;
import net.neoforged.neoforge.common.ModConfigSpec;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.tick.ServerTickEvent;
import net.neoforged.neoforge.network.configuration.ICustomConfigurationTask;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * BotPass: one trusted bot (default name "claude") may join an online-mode server without a Mojang account, but only
 * if it proves it knows the server's secret.
 * <ol>
 * <li>Login: a bot name skips Mojang's check (see the login mixin); everybody else logs in normally.</li>
 * <li>Configuration: the server sends a random challenge; the bot answers with HMAC-SHA256(secret, challenge) and
 * its machine name. The secret itself never travels over the network.</li>
 * <li>Wrong answer, no answer within 15 s, no BotPass on the client, a machine or IP that isn't allowed: kicked,
 * the IP banned (24 h by default), and every op online gets an alert.</li>
 * </ol>
 * The secret is made on the first start, in config/botpass/secret.txt. Copy that file to the same place in the bot's
 * game folder. Never share it.
 */
@Mod(BotPass.MODID)
public final class BotPass {
    public static final String MODID = "botpass";
    private static final Logger LOG = LogUtils.getLogger();
    static final Path SECRET = FMLPaths.CONFIGDIR.get().resolve("botpass/secret.txt");

    // ---- Config ----
    public static final ModConfigSpec SPEC;
    public static final ModConfigSpec.ConfigValue<List<? extends String>> NAMES, IPS, MACHINES;
    public static final ModConfigSpec.IntValue BAN_MINUTES;

    static {
        ModConfigSpec.Builder b = new ModConfigSpec.Builder();
        NAMES = b.comment("Bot names that may skip the Mojang login (they must still prove the secret)")
                .defineListAllowEmpty("botNames", List.of("claude"), () -> "", o -> o instanceof String s && !s.isBlank());
        IPS = b.comment("Only these IPs may log in as a bot (empty = any IP; the secret is still required)")
                .defineListAllowEmpty("allowedIps", List.of(), () -> "", o -> o instanceof String);
        MACHINES = b.comment("Only bots on these computers (by name, e.g. MY-PC) may log in (empty = any; an extra check, the secret is the real lock)")
                .defineListAllowEmpty("allowedMachines", List.of(), () -> "", o -> o instanceof String);
        BAN_MINUTES = b.comment("How long an IP that failed is banned").defineInRange("banMinutes", 1440, 1, 525600);
        SPEC = b.build();
    }

    public BotPass(IEventBus modBus, ModContainer container) {
        container.registerConfig(ModConfig.Type.SERVER, SPEC);
        modBus.addListener(BotPass::payloads);
        modBus.addListener(BotPass::tasks);
        NeoForge.EVENT_BUS.register(BotPass.class);
    }

    // ---- State ----
    record Pending(String name, long since, byte[] challenge) {}

    private static final Map<Connection, Pending> PENDING = new ConcurrentHashMap<>();
    private static final Map<String, Long> BANNED = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String ip(SocketAddress a) {
        return a instanceof InetSocketAddress i && i.getAddress() != null ? i.getAddress().getHostAddress() : String.valueOf(a);
    }

    public static boolean banned(String ip) {
        Long until = BANNED.get(ip);
        if (until == null) return false;
        if (System.currentTimeMillis() < until) return true;
        BANNED.remove(ip);
        return false;
    }

    public static boolean isBotName(String name) {
        return NAMES.get().stream().anyMatch(n -> n.equalsIgnoreCase(name));
    }

    public static boolean ipAllowed(String ip) {
        return IPS.get().isEmpty() || IPS.get().contains(ip);
    }

    public static boolean machineAllowed(String machine) {
        return MACHINES.get().isEmpty() || MACHINES.get().stream().anyMatch(m -> m.equalsIgnoreCase(machine));
    }

    public static void pending(Connection c, String name) {
        byte[] challenge = new byte[32];
        RANDOM.nextBytes(challenge);
        PENDING.put(c, new Pending(name, System.currentTimeMillis(), challenge));
    }

    /** A failed bot login: ban the IP for a while and tell every op online. */
    public static void fail(MinecraftServer server, Connection c, String name, String ip, String why) {
        PENDING.remove(c);
        BANNED.put(ip, System.currentTimeMillis() + BAN_MINUTES.get() * 60_000L);
        LOG.warn("BotPass: refused '{}' from {} ({}); IP banned for {} minutes", name, ip, why, BAN_MINUTES.get());
        Component alert = Component.translatable("botpass.alert", name, ip, Component.translatable("botpass.why." + why)).withStyle(ChatFormatting.RED);
        server.execute(() -> {
            for (ServerPlayer op : server.getPlayerList().getPlayers())
                if (server.getPlayerList().isOp(op.getGameProfile())) op.sendSystemMessage(alert);
        });
    }

    // ---- The secret ----

    /** The server's secret (made on first use). Only ever read locally; it is never sent anywhere. */
    static byte[] secret(boolean create) {
        try {
            if (!Files.exists(SECRET)) {
                if (!create) return null;
                Files.createDirectories(SECRET.getParent());
                byte[] s = new byte[32];
                RANDOM.nextBytes(s);
                Files.writeString(SECRET, HexFormat.of().formatHex(s));
                try {
                    Files.setPosixFilePermissions(SECRET, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
                } catch (UnsupportedOperationException ignored) { // Windows
                }
                LOG.info("BotPass: made a new secret in {}. Copy it to the same place in the bot's game folder.", SECRET);
            }
            return HexFormat.of().parseHex(Files.readString(SECRET).trim());
        } catch (Exception e) {
            LOG.error("BotPass: can't read {}", SECRET, e);
            return null;
        }
    }

    public static byte[] proof(byte[] secret, byte[] challenge) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(challenge);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- Network ----

    public record Challenge(byte[] nonce) implements CustomPacketPayload {
        public static final Type<Challenge> TYPE = new Type<>(ResourceLocation.fromNamespaceAndPath(MODID, "challenge"));
        public static final StreamCodec<ByteBuf, Challenge> CODEC = ByteBufCodecs.BYTE_ARRAY.map(Challenge::new, Challenge::nonce);

        @Override
        public Type<? extends CustomPacketPayload> type() {
            return TYPE;
        }
    }

    public record Answer(byte[] proof, String machine) implements CustomPacketPayload {
        public static final Type<Answer> TYPE = new Type<>(ResourceLocation.fromNamespaceAndPath(MODID, "answer"));
        public static final StreamCodec<ByteBuf, Answer> CODEC = StreamCodec.composite(ByteBufCodecs.BYTE_ARRAY, Answer::proof,
                ByteBufCodecs.STRING_UTF8, Answer::machine, Answer::new);

        @Override
        public Type<? extends CustomPacketPayload> type() {
            return TYPE;
        }
    }

    private static void payloads(RegisterPayloadHandlersEvent event) {
        var r = event.registrar("1").optional();
        r.configurationToClient(Challenge.TYPE, Challenge.CODEC, BotPass::onChallenge);
        r.configurationToServer(Answer.TYPE, Answer.CODEC, BotPass::onAnswer);
    }

    /** Bot side: answer the challenge with the secret from this game folder. */
    private static void onChallenge(Challenge c, IPayloadContext ctx) {
        byte[] s = secret(false);
        String machine = System.getenv().getOrDefault("BOTPASS_MACHINE", hostName());
        ctx.reply(new Answer(s == null ? new byte[0] : proof(s, c.nonce()), machine));
    }

    static String hostName() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName().replaceAll("\\.local$", "");
        } catch (Exception e) {
            return "";
        }
    }

    /** Server side: check the bot's answer. */
    private static void onAnswer(Answer a, IPayloadContext ctx) {
        Connection c = ctx.connection();
        Pending p = PENDING.remove(c);
        if (p == null) return; // not a bot login: nothing to check
        MinecraftServer server = net.neoforged.neoforge.server.ServerLifecycleHooks.getCurrentServer();
        String ip = ip(c.getRemoteAddress());
        byte[] s = secret(true);
        boolean ok = s != null && a.proof().length > 0 && MessageDigest.isEqual(proof(s, p.challenge()), a.proof());
        if (ok && !machineAllowed(a.machine())) {
            if (server != null) fail(server, c, p.name(), ip, "machine");
            ctx.disconnect(Component.translatable("botpass.refused"));
            return;
        }
        if (!ok) {
            if (server != null) fail(server, c, p.name(), ip, "secret");
            ctx.disconnect(Component.translatable("botpass.refused"));
            return;
        }
        LOG.info("BotPass: '{}' proved the secret from {} ({})", p.name(), ip, a.machine());
        ctx.finishCurrentTask(Task.TYPE);
    }

    // ---- The configuration task: only for bot logins ----

    record Task(Connection connection) implements ICustomConfigurationTask {
        static final ConfigurationTask.Type TYPE = new ConfigurationTask.Type(ResourceLocation.fromNamespaceAndPath(MODID, "check"));

        @Override
        public void run(Consumer<CustomPacketPayload> sender) {
            Pending p = PENDING.get(connection);
            if (p != null) sender.accept(new Challenge(p.challenge()));
        }

        @Override
        public Type type() {
            return TYPE;
        }
    }

    private static void tasks(RegisterConfigurationTasksEvent event) {
        if (!(event.getListener() instanceof ServerCommonPacketListenerImpl l)) return;
        Connection c = l.getConnection();
        if (!PENDING.containsKey(c)) return;
        if (!event.getListener().hasChannel(Challenge.TYPE)) {
            fail(net.neoforged.neoforge.server.ServerLifecycleHooks.getCurrentServer(), c, PENDING.get(c).name(), ip(c.getRemoteAddress()), "no_mod");
            l.disconnect(Component.translatable("botpass.refused"));
            return;
        }
        event.register(new Task(c));
    }

    // Make the secret as soon as the server starts, so it can be copied to the bot.
    @SubscribeEvent
    public static void onStarted(net.neoforged.neoforge.event.server.ServerStartedEvent event) {
        if (event.getServer().isDedicatedServer()) secret(true);
    }

    // No answer in 15 seconds: out.
    @SubscribeEvent
    public static void onTick(ServerTickEvent.Post event) {
        if (event.getServer().getTickCount() % 20 != 0 || PENDING.isEmpty()) return;
        long now = System.currentTimeMillis();
        for (var e : PENDING.entrySet())
            if (now - e.getValue().since() > 15_000) {
                Connection c = e.getKey();
                fail(event.getServer(), c, e.getValue().name(), ip(c.getRemoteAddress()), "timeout");
                c.disconnect(Component.translatable("botpass.refused"));
            }
    }

    // For the GameTests.
    public static void clearBans() {
        BANNED.clear();
    }
}
