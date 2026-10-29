package dev.ghostlock.bootstrap

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Bundle
import android.provider.Settings
import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import io.github.rhythmcache.adb.AdbClient
import io.github.rhythmcache.adb.FileKeyProvider
import io.github.rhythmcache.adb.ShellChunk
import io.github.rhythmcache.adb.pairing.PeerInfoBuilder
import io.github.rhythmcache.adb.pairing.PeerInfoType
import io.github.rhythmcache.adb.pairing.buildPairingIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.collect
import java.io.File
import java.net.InetAddress
import java.net.NetworkInterface
import java.security.MessageDigest
import java.util.UUID
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val ADB_HOST = "127.0.0.1"
private const val EXPECTED_MODEL = "SM-A156U"
private const val EXPECTED_KERNEL = "5.15.189-android13-8-33641424"
private const val EXPECTED_FINGERPRINT = "samsung/a15xsq/a15x:16/BP4A.251205.006/A156USQSCEZG1:user/release-keys"
private const val EXPECTED_BOOTLOADER = "A156USQSCEZG1"
private const val REMOTE_DIR = "/data/local/tmp/ghostlock-a15-session"
private const val REMOTE_CANDIDATE = "$REMOTE_DIR/e"
private const val REMOTE_G4D = "/data/local/tmp/a/g4d"
private const val REMOTE_G4SH = "/data/local/tmp/a/g4sh"
private const val REMOTE_G4D_SU = "/data/local/tmp/a/g4d-su"
private const val REMOTE_G4SU = "/data/local/tmp/a/g4su"
private const val REMOTE_G4MOUNT = "/data/local/tmp/a/g4mount"
private const val REMOTE_G4EXEC = "/data/local/tmp/a/g4exec"
private const val REMOTE_DEFEX = "/data/local/tmp/a/defex-exec.sh"
private const val REMOTE_ALLOW = "/dev/ghostlock-g4d.allow"
private const val REMOTE_SU_PID = "/dev/ghostlock-g4d-su.pid"
private const val OLD_G4D_SHA256 = "34f542e0f9f91e8c67b0a13f23da527c2c8f906ece2c5ad40850dcedad23b651"
private const val PREVIOUS_G4EXEC_SHA256 = "5158acd142ca93582dc96b86f6ec8165bfd51af43385f3aa5d4db5e6b2801348"
private const val PREVIOUS_DEFEX_SHA256 = "61ca6c26c91f56ea5fbaa98e022224b928a77a6f01f5d71730f2a62ec1047144"
private const val ROOT_COMMAND_TIMEOUT_MS = 20_000L

private val PREVIOUS_MANAGER_HASHES = mapOf(
    "g4d-su" to setOf(
        "4800d0d28b13511f61e119cc92f40968d1812c37488a7efcf66c7ae597cef0fd",
        "199ef51e3fd567fe35353379a45707f14e9a174cc67b23d5ef5211eb284b2d7f",
        "e64e8e608e215075efcedc61112bc9943543d45b21265ad301f85214eac36727",
        "efdbf46d08105aef868cccb2d621c263c030b89d7e6dacb088f66528f0ec36e6",
        "5608f51e55577d01512c43f7835d59c805b6d28497cd5f91314e87896216e592",
    ),
    "g4su" to setOf(
        "bcdc4d7afb546bd7ee6769e91c620633326c831f967d08d77aa9d8b9e4c67f68",
        "571425bd967359402a5c01d025dbda4af0a103fd96781d9fb1f81bde8d44f3d2",
        "655da7cc465300b3162b061f19d23f5f4ae5e0db671afcc706769377b92228b0",
        "211b175a0c630b4bbc141b45f478b49b1ce064244e3f4697a814e43dfa33675e",
        "03f761f113d0fdcb00e7c46a5be28d1f3a30a98d304ed47050033d5ce1296176",
        "b7f116363e347e4f0f0e11619af8fb31f699f02b1434c17053af395c739891e6",
        "a1d2d365e9380f705528cf54a7813d4ed0eace30fd0f71e293e566d387fa41d7",
    ),
    "g4mount" to setOf(
        "61a6f9117d22623c5cfa11bbd9f1449d9d024ee264388585697bd17453c2b9ac",
        "c865a18cf9b11e2b7645ae73729f30bbf2f9ab865c007e2d0c4e2cc61c3449f5",
        "ef3e3d02e76e856920bda0eb12f1c547306ee73b399f309fd90d40c2ecca8720",
        "5c1c946e0fdb28de4253f8fff9b8a58e4337d7345f0564ad213f94f782104e3a",
        "ec35bf15affe0eb5a179bad0b51af03a05403b3d495f1bd1d229121f976e9ce8",
        "4e80342fac33ac563c612cc927091f301926aa89380da9fa8889da47a50af75a",
        "42855b6f60a03ec3f6b2d4666465e86ec8bc260e3a3a918c63196d5d7887bb61",
        "bf70fb654a8846acb0e1102784e9bca409b47e4b3419cf8e2209d62d1a954ac8",
        "6de7f0836ae44df3a79ab23898118757ee6e53d39830a5d883695e1bdf20cdb1",
        "1ce203f3808958135fd9f70df05dfaf38327306ff373464e890447bcdf2eb574",
    ),
)

private data class Payload(
    val asset: String,
    val path: String,
    val sha256: String,
)

private data class UiInputs(
    val pairPort: String,
    val pairingCode: String,
    val connectPort: String,
)

private val PAYLOADS = listOf(
    Payload("ghostlock-a15", REMOTE_CANDIDATE, "392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617"),
    Payload("g4d", REMOTE_G4D, "9664ec30c732f39ea8978cfbe3add7c3a68459ea1c3cb5b324ac6d306238dab5"),
    Payload("g4sh", REMOTE_G4SH, "ffd2dbf559967b6219b2c02481f0f402f919477e644a1d4e8548bdda751a1326"),
)

private val MANAGER_PAYLOADS = listOf(
    Payload("g4d-su", REMOTE_G4D_SU, "d3ae0d0bfba8beb0aabd101d56d01f82484ab227bfe2111f15cd939f777249aa"),
    Payload("g4su", REMOTE_G4SU, "90ad28ac750f300682bb30290fe2fa0ec2aa6cff32ac210268fbb1b7c8e8544b"),
    Payload("g4mount", REMOTE_G4MOUNT, "8dbbb8ccee5629079eadb6b1d2f561068675a7ba81bab53613d08ac87c1c6b06"),
    Payload("g4exec", REMOTE_G4EXEC, "d431fb90b3525f5667a69105391caf44cb51cf6e91ec708f98343575366254fa"),
    Payload("defex-exec.sh", REMOTE_DEFEX, "aa8169c254a7f6d8dd52949b25a7a17d37c59e2586849ea9a4a327461026b53d"),
)

private data class RootResult(val output: String, val exitCode: Int)
private data class AppUidGroup(val uid: Int, val title: String)

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var pairPortInput: EditText
    private lateinit var pairingCodeInput: EditText
    private lateinit var connectPortInput: EditText
    private lateinit var output: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var logScrollView: ScrollView
    private lateinit var statusBanner: TextView
    private lateinit var exploitPanel: LinearLayout
    private lateinit var managerPanel: LinearLayout
    private lateinit var exploitTabButton: TextView
    private lateinit var managerTabButton: TextView
    private lateinit var exploitTabIndicator: android.view.View
    private lateinit var managerTabIndicator: android.view.View
    private lateinit var stageExploitButton: Button
    private lateinit var triggerExploitButton: Button
    private lateinit var cleanStagedButton: Button
    private lateinit var exploitStageStatus: TextView
    private lateinit var prepareManagerButton: Button
    private lateinit var managerPreparedStatus: TextView
    private lateinit var retryPairButton: Button
    private lateinit var wirelessSetupPanel: LinearLayout
    private lateinit var pairedStatus: TextView
    private val actionButtons = mutableListOf<Button>()
    private var busy = false
    private var statusCheckRunning = false
    private var exploitPayloadStaged = false
    private var stagedFilesExist = false
    private var lastAutoPairAttempt: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildScreen()
        val guid = getSharedPreferences("adb-pairing", MODE_PRIVATE).getString("device_guid", null)
        setPairedUi(false)
        if (guid != null) append("Paired Wireless Debugging identity is saved: $guid")
        append("This is a one-boot bootstrap only. It does not flash boot, vbmeta, recovery, or system partitions.")
    }

    override fun onResume() {
        super.onResume()
        refreshExploitStatus()
    }

    override fun onDestroy() {
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
        super.onDestroy()
    }

    private fun buildScreen() {
        val scroll = ScrollView(this).also { scrollView = it }
        scroll.fitsSystemWindows = true
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(28))
        }
        scroll.addView(column)

        column.addView(TextView(this).apply {
            text = "GhostSlop A15 root manager"
            textSize = 24f
            setTextColor(0xff202124.toInt())
        })
        column.addView(TextView(this).apply {
            text = "One-boot root access. No boot image or system partition changes."
            textSize = 14f
            setPadding(0, dp(4), 0, dp(10))
        })

        statusBanner = TextView(this).apply {
            text = "Checking exploit status…"
            textSize = 16f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(0xffffffff.toInt())
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setBackgroundColor(0xff5f6368.toInt())
        }
        column.addView(statusBanner, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        val tabStrip = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        exploitTabButton = addTab(tabs, "Exploit") { showTab(showManager = false) }
        managerTabButton = addTab(tabs, "Root Manager") { showTab(showManager = true) }
        tabStrip.addView(tabs, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        val tabIndicators = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(0xffdadce0.toInt())
        }
        exploitTabIndicator = android.view.View(this).apply { setBackgroundColor(0xff1a73e8.toInt()) }
        managerTabIndicator = android.view.View(this).apply { setBackgroundColor(android.graphics.Color.TRANSPARENT) }
        tabIndicators.addView(exploitTabIndicator, LinearLayout.LayoutParams(0, dp(2), 1f))
        tabIndicators.addView(managerTabIndicator, LinearLayout.LayoutParams(0, dp(2), 1f))
        tabStrip.addView(tabIndicators, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(2)))
        column.addView(tabStrip, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(8)
        })

        exploitPanel = newPanel()
        managerPanel = newPanel()
        column.addView(exploitPanel)
        column.addView(managerPanel)

        wirelessSetupPanel = newPanel()
        addText(wirelessSetupPanel, "Wireless Debugging connection")
        addText(wirelessSetupPanel, "In Android Settings, enable Wireless debugging and open ‘Pair device with pairing code’. Enter its port and six-digit code below; pairing and connect-port discovery start automatically.")
        addButton(wirelessSetupPanel, "Open Developer options") {
            startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
        }
        pairPortInput = addNumberField(wirelessSetupPanel, "Pairing port")
        pairingCodeInput = addNumberField(wirelessSetupPanel, "Six-digit pairing code", maxLength = 6)
        retryPairButton = addButton(wirelessSetupPanel, "Retry pairing") {
            runAction("Pairing and discovering connect port", onSuccess = {
                lastAutoPairAttempt = null
                retryPairButton.visibility = ViewGroup.GONE
            }) { pairAndDiscover(it) }
        }.also { it.visibility = ViewGroup.GONE }
        val pairingWatcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) = maybeAutoPair()
        }
        pairPortInput.addTextChangedListener(pairingWatcher)
        pairingCodeInput.addTextChangedListener(pairingWatcher)
        connectPortInput = addNumberField(wirelessSetupPanel, "Connect port override (optional)")
        exploitPanel.addView(wirelessSetupPanel)
        pairedStatus = addText(exploitPanel, "Wireless Debugging paired. Connect-port discovery is automatic.")
            .also { it.visibility = ViewGroup.GONE }
        stageExploitButton = addButton(exploitPanel, "Check & stage exploit") {
            runAction("Checking target and staging exploit") { stagePayload(it) }
        }
        triggerExploitButton = addButton(exploitPanel, "Trigger exploit once", danger = true) { confirmTrigger() }
            .also { it.visibility = ViewGroup.GONE }
        exploitStageStatus = addText(exploitPanel, "")
            .also { it.visibility = ViewGroup.GONE }
        cleanStagedButton = addButton(exploitPanel, "Clean staged files (after reboot)") {
            runAction("Cleaning staged files", onSuccess = {
                cleanStagedButton.visibility = ViewGroup.GONE
                exploitPayloadStaged = false
                stagedFilesExist = false
                stageExploitButton.visibility = ViewGroup.VISIBLE
                exploitStageStatus.visibility = ViewGroup.GONE
            }) { cleanStagedFiles(it) }
        }.also { it.visibility = ViewGroup.GONE }

        addText(managerPanel, "Applying app selection grants those UIDs. Packages sharing a UID share root access. Prepare checks the ADB-side daemon; Test this app checks app-process su launch.")
        addText(managerPanel, "Compatibility experiment: su links to a RAM-backed, system_file-labeled g4su copy in app zygote namespaces. Reboot removes the overlay.")
        managerPreparedStatus = addText(managerPanel, "Manager prepared for this boot.")
            .also { it.visibility = ViewGroup.GONE }
        prepareManagerButton = addButton(managerPanel, "Prepare manager") {
            runAction("Preparing root manager") { prepareRootManager(it) }
        }
        addButton(managerPanel, "Choose apps & enable su") { openGrantManager() }
        addButton(managerPanel, "Remove su entrypoint") {
            runAction("Removing su entrypoint") { manageSuOverlay(it, "remove") }
        }
        addButton(managerPanel, "Check manager status") {
            runAction("Checking manager") { managerStatus(it) }
        }
        addButton(managerPanel, "Test this app's su access") {
            runAction("Testing this app's su access") { testCurrentAppSu() }
        }
        showTab(showManager = false)

        output = TextView(this).apply {
            textSize = 13f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextColor(0xff202124.toInt())
            setTextIsSelectable(true)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setBackgroundColor(0xfff1f3f4.toInt())
            text = "Ready."
        }
        logScrollView = ScrollView(this).apply {
            isFillViewport = true
            isNestedScrollingEnabled = true
            isVerticalScrollBarEnabled = true
            addView(output, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        column.addView(logScrollView, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(260)).apply {
            topMargin = dp(18)
        })
        setContentView(scroll)
    }

    private fun newPanel() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(4), 0, dp(8))
    }

    private fun addTab(parent: LinearLayout, title: String, action: () -> Unit): TextView {
        val tab = TextView(this).apply {
            text = title
            textSize = 14f
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(12), dp(12), dp(12))
            isClickable = true
            isFocusable = true
            setOnClickListener { action() }
        }
        parent.addView(tab, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        return tab
    }

    private fun showTab(showManager: Boolean) {
        if (!::exploitPanel.isInitialized || !::managerPanel.isInitialized) return
        exploitPanel.visibility = if (showManager) ViewGroup.GONE else ViewGroup.VISIBLE
        managerPanel.visibility = if (showManager) ViewGroup.VISIBLE else ViewGroup.GONE
        exploitTabButton.isSelected = !showManager
        managerTabButton.isSelected = showManager
        exploitTabButton.setTextColor(if (showManager) 0xff5f6368.toInt() else 0xff1a73e8.toInt())
        managerTabButton.setTextColor(if (showManager) 0xff1a73e8.toInt() else 0xff5f6368.toInt())
        exploitTabButton.setTypeface(null, if (showManager) android.graphics.Typeface.NORMAL else android.graphics.Typeface.BOLD)
        managerTabButton.setTypeface(null, if (showManager) android.graphics.Typeface.BOLD else android.graphics.Typeface.NORMAL)
        exploitTabIndicator.setBackgroundColor(if (showManager) android.graphics.Color.TRANSPARENT else 0xff1a73e8.toInt())
        managerTabIndicator.setBackgroundColor(if (showManager) 0xff1a73e8.toInt() else android.graphics.Color.TRANSPARENT)
    }

    private fun addText(parent: LinearLayout, value: String): TextView {
        val textView = TextView(this).apply {
            text = value
            textSize = 14f
            setPadding(0, dp(12), 0, dp(5))
        }
        parent.addView(textView)
        return textView
    }

    private fun addNumberField(parent: LinearLayout, hint: String, maxLength: Int = 5): EditText {
        val edit = EditText(this).apply {
            this.hint = hint
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(maxLength))
            isSingleLine = true
        }
        parent.addView(edit, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        return edit
    }

    private fun addButton(parent: LinearLayout, title: String, danger: Boolean = false, action: () -> Unit): Button {
        val button = Button(this).apply {
            text = title
            gravity = Gravity.CENTER
            if (danger) setTextColor(0xffb3261e.toInt())
            setOnClickListener { action() }
        }
        actionButtons += button
        parent.addView(button, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(4)
        })
        return button
    }

    private fun maybeAutoPair() {
        if (busy || !::retryPairButton.isInitialized) return
        val inputs = currentInputs()
        val port = inputs.pairPort.toIntOrNull()?.takeIf { it in 1..65535 }
        val code = inputs.pairingCode
        if (port == null || code.length != 6 || !code.all(Char::isDigit)) {
            if (code.length < 6 || port == null) lastAutoPairAttempt = null
            retryPairButton.visibility = ViewGroup.GONE
            return
        }
        val attempt = "$port:$code"
        if (lastAutoPairAttempt == attempt) return
        lastAutoPairAttempt = attempt
        retryPairButton.visibility = ViewGroup.GONE
        runAction("Pairing and discovering connect port", onSuccess = {
            lastAutoPairAttempt = null
            retryPairButton.visibility = ViewGroup.GONE
        }) { pairAndDiscover(it) }
    }

    private fun runAction(
        label: String,
        onSuccess: ((String) -> Unit)? = null,
        action: suspend (UiInputs) -> String,
    ) {
        if (busy) return
        val inputs = currentInputs()
        setBusy(true)
        append("$label…")
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) { action(inputs) }
                append(result)
                onSuccess?.invoke(result)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                append("ERROR: ${e.message ?: e.javaClass.simpleName}")
                if (label.startsWith("Pairing")) {
                    lastAutoPairAttempt = null
                    retryPairButton.visibility = ViewGroup.VISIBLE
                }
            } finally {
                setBusy(false)
                if (label.startsWith("Pairing") || label == "One-shot trigger") refreshExploitStatus()
            }
        }
    }

    private fun currentInputs() = UiInputs(
        pairPortInput.text.toString(),
        pairingCodeInput.text.toString(),
        connectPortInput.text.toString(),
    )

    private fun setBusy(value: Boolean) {
        busy = value
        if (value) window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        actionButtons.forEach { it.isEnabled = !value }
    }

    private fun refreshExploitStatus() {
        if (!::statusBanner.isInitialized || busy || statusCheckRunning) return
        val guid = getSharedPreferences("adb-pairing", MODE_PRIVATE).getString("device_guid", null)
        if (guid.isNullOrBlank()) {
            setExploitStatus(null)
            setManagerPrepared(false)
            setExploitPayloadStaged(false, false)
            return
        }
        statusCheckRunning = true
        statusBanner.text = "Checking exploit status…"
        val inputs = currentInputs()
        scope.launch {
            try {
                val state = withContext(Dispatchers.IO) {
                    withAdb(inputs) { client ->
                        val result = commandAllowFailure(client, "$REMOTE_G4SH -c 'id -u'")
                        val active = result.exitCode == 0 && result.stdoutText.lineSequence().any { it.trim() == "0" }
                        val bootId = commandAllowFailure(client, "cat /proc/sys/kernel/random/boot_id")
                            .stdoutText.trim().takeIf { it.matches(Regex("[0-9a-fA-F-]{36}")) }
                        val prefs = getSharedPreferences("manager-state", MODE_PRIVATE)
                        val recordedBoot = prefs.getString("manager_boot_id", null)
                        val managerHashCheck = if (active && bootId != null && recordedBoot == bootId) {
                            rootCommand(
                                client,
                                MANAGER_PAYLOADS.joinToString(" ") { "sha256sum '${it.path}'" },
                            )
                        } else RootResult("", 1)
                        val managerHashes = managerHashCheck.output.lineSequence().mapNotNull { line ->
                            val path = line.substringAfterLast(' ', "")
                            val hash = line.substringBefore(' ').lowercase()
                            if (path.isNotEmpty() && hash.matches(Regex("[0-9a-f]{64}"))) path to hash else null
                        }.toMap()
                        val managerPayloadsCurrent = managerHashCheck.exitCode == 0 &&
                            MANAGER_PAYLOADS.all { managerHashes[it.path] == it.sha256 }
                        val managerPrepared = active && bootId != null && recordedBoot == bootId &&
                            managerPayloadsCurrent && rootCommand(
                                client,
                                "test -x '$REMOTE_G4MOUNT' && test -x '$REMOTE_G4SU' && test -x '$REMOTE_G4EXEC' && test -r '$REMOTE_DEFEX'",
                            ).exitCode == 0 && runDefexTarget(client, REMOTE_G4SU, listOf("-c", "id -u"))
                                .let { it.exitCode == 0 && it.output.lineSequence().any { line -> line.trim() == "0" } }
                        if (recordedBoot != null && bootId != null && recordedBoot != bootId) {
                            prefs.edit().remove("manager_boot_id").apply()
                        }
                        val recordedStageBoot = prefs.getString("staged_boot_id", null)
                        val stageHashes = if (!active) {
                            val remote = commandAllowFailure(
                                client,
                                "sha256sum ${PAYLOADS.joinToString(" ") { "'${it.path}'" }}",
                            )
                            if (remote.exitCode == 0) {
                                val hashes = remote.stdoutText.lineSequence().mapNotNull { line ->
                                    val path = line.substringAfterLast(' ', "")
                                    val hash = line.substringBefore(' ').lowercase()
                                    if (path.isNotEmpty() && hash.matches(Regex("[0-9a-f]{64}"))) path to hash else null
                                }.toMap()
                                PAYLOADS.all { hashes[it.path] == it.sha256 }
                            } else false
                        } else false
                        val filesExist = if (!active) {
                            commandAllowFailure(
                                client,
                                PAYLOADS.joinToString(" || ") { "test -e '${it.path}'" },
                            ).exitCode == 0
                        } else false
                        Triple(
                            active,
                            managerPrepared,
                            (stageHashes && recordedStageBoot == bootId && filesExist) to filesExist,
                        )
                    }
                }
                setPairedUi(true)
                setExploitStatus(state.first)
                setManagerPrepared(state.second)
                setExploitPayloadStaged(state.third.first, state.third.second)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                val pairingSaved = !guid.isNullOrBlank()
                setPairedUi(pairingSaved)
                if (pairingSaved) {
                    pairedStatus.text = "Wireless Debugging identity is saved, but status could not be checked. Enable Wireless Debugging and reconnect."
                }
                setExploitStatus(null)
            } finally {
                statusCheckRunning = false
            }
        }
    }

    private fun setExploitStatus(active: Boolean?) {
        if (!::statusBanner.isInitialized) return
        when (active) {
            true -> {
                statusBanner.text = "EXPLOIT ACTIVE"
                statusBanner.setBackgroundColor(0xff188038.toInt())
                if (::stageExploitButton.isInitialized) stageExploitButton.visibility = ViewGroup.GONE
                if (::triggerExploitButton.isInitialized) triggerExploitButton.visibility = ViewGroup.GONE
                if (::cleanStagedButton.isInitialized) cleanStagedButton.visibility = ViewGroup.GONE
                if (::exploitStageStatus.isInitialized) {
                    exploitStageStatus.text = "One-boot root is active. Exploit staging and trigger are no longer needed."
                    exploitStageStatus.visibility = ViewGroup.VISIBLE
                }
            }
            false -> {
                statusBanner.text = "EXPLOIT NOT ACTIVE"
                statusBanner.setBackgroundColor(0xffb3261e.toInt())
                if (::stageExploitButton.isInitialized) {
                    stageExploitButton.visibility = if (exploitPayloadStaged) ViewGroup.GONE else ViewGroup.VISIBLE
                }
                if (::triggerExploitButton.isInitialized) {
                    triggerExploitButton.visibility = if (exploitPayloadStaged) ViewGroup.VISIBLE else ViewGroup.GONE
                }
                if (::cleanStagedButton.isInitialized) {
                    cleanStagedButton.visibility = if (stagedFilesExist) ViewGroup.VISIBLE else ViewGroup.GONE
                }
                if (::exploitStageStatus.isInitialized) {
                    exploitStageStatus.text = when {
                        exploitPayloadStaged -> "Exploit files are staged for this boot."
                        stagedFilesExist -> "Files from a previous boot remain. Check & stage before triggering."
                        else -> ""
                    }
                    exploitStageStatus.visibility = if (exploitPayloadStaged || stagedFilesExist) ViewGroup.VISIBLE else ViewGroup.GONE
                }
            }
            null -> {
                statusBanner.text = "ROOT STATUS UNKNOWN"
                statusBanner.setBackgroundColor(0xff5f6368.toInt())
            }
        }
    }

    private fun setManagerPrepared(prepared: Boolean) {
        if (!::prepareManagerButton.isInitialized || !::managerPreparedStatus.isInitialized) return
        prepareManagerButton.visibility = if (prepared) ViewGroup.GONE else ViewGroup.VISIBLE
        managerPreparedStatus.visibility = if (prepared) ViewGroup.VISIBLE else ViewGroup.GONE
    }

    private fun setPairedUi(paired: Boolean) {
        if (!::wirelessSetupPanel.isInitialized || !::pairedStatus.isInitialized) return
        wirelessSetupPanel.visibility = if (paired) ViewGroup.GONE else ViewGroup.VISIBLE
        pairedStatus.visibility = if (paired) ViewGroup.VISIBLE else ViewGroup.GONE
    }

    private fun setExploitPayloadStaged(staged: Boolean, filesExist: Boolean = staged) {
        if (!::stageExploitButton.isInitialized || !::triggerExploitButton.isInitialized ||
            !::cleanStagedButton.isInitialized || !::exploitStageStatus.isInitialized) return
        exploitPayloadStaged = staged
        stagedFilesExist = filesExist
        if (staged) {
            stageExploitButton.visibility = ViewGroup.GONE
            triggerExploitButton.visibility = ViewGroup.VISIBLE
            cleanStagedButton.visibility = ViewGroup.VISIBLE
            exploitStageStatus.text = "Exploit files are staged for this boot."
            exploitStageStatus.visibility = ViewGroup.VISIBLE
        } else if (statusBanner.text != "EXPLOIT ACTIVE") {
            stageExploitButton.visibility = ViewGroup.VISIBLE
            triggerExploitButton.visibility = ViewGroup.GONE
            cleanStagedButton.visibility = if (stagedFilesExist) ViewGroup.VISIBLE else ViewGroup.GONE
            exploitStageStatus.text = if (stagedFilesExist) "Files from a previous boot remain. Check & stage before triggering." else ""
            exploitStageStatus.visibility = if (stagedFilesExist) ViewGroup.VISIBLE else ViewGroup.GONE
        }
    }

    private fun confirmTrigger() {
        AlertDialog.Builder(this)
            .setTitle("Run one kernel exploit attempt?")
            .setMessage(
                "This executes the pinned exploit once against the currently running kernel. It does not write boot, vbmeta, recovery, or system partitions, but a failed kernel exploit can still panic or reboot the phone. The app will not retry this boot. Continue only after the target check passes and the payload is staged.",
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Trigger once") { _, _ -> runAction("One-shot trigger") { triggerOnce(it) } }
            .show()
    }

    private fun confirmGrantSelection(selected: Set<Int>) {
        val hasApps = selected.isNotEmpty()
        AlertDialog.Builder(this)
            .setTitle(if (hasApps) "Apply root access and enable su?" else "Clear app root grants?")
            .setMessage(if (hasApps) {
                "This applies the selected UID grants and automatically mounts the temporary /system/bin/su entrypoint in live zygote namespaces. It ends at reboot. Existing apps may need to be force-stopped and reopened."
            } else {
                "No apps are selected. Applying this clears current-boot app grants and leaves the su entrypoint unchanged."
            })
            .setNegativeButton("Cancel", null)
            .setPositiveButton(if (hasApps) "Apply & enable" else "Apply") { _, _ ->
                runAction("Applying app root access") { inputs ->
                    val grants = applyGrants(inputs, selected)
                    if (hasApps) "$grants\n${manageSuOverlay(inputs, "install")}" else grants
                }
            }
            .show()
    }

    private suspend fun pair(inputs: UiInputs): String {
        val port = inputs.pairPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: error("Enter the pairing port shown by Wireless Debugging.")
        val code = inputs.pairingCode
        require(code.length == 6 && code.all(Char::isDigit)) { "Enter the six-digit pairing code." }
        val keys = keyProvider()
        val result = AdbClient.pairTls(ADB_HOST, port, code, keys).getOrElse { throw it }
        require(result.peerInfo.type == PeerInfoType.ADB_DEVICE_GUID) {
            "Pairing returned an unexpected peer type: ${result.peerInfo.type}"
        }
        val guid = PeerInfoBuilder.extractDeviceGuid(result.peerInfo)
        require(guid.isNotBlank()) { "Pairing completed without a device identity." }
        getSharedPreferences("adb-pairing", MODE_PRIVATE).edit().putString("device_guid", guid).apply()
        withContext(Dispatchers.Main) {
            pairingCodeInput.text.clear()
            setPairedUi(true)
        }
        return "Wireless Debugging pairing succeeded. Device GUID: $guid"
    }

    private suspend fun pairAndDiscover(inputs: UiInputs): String {
        val paired = pair(inputs)
        return try {
            val discovered = discoverConnectPort()
            "$paired\n$discovered. The connect port is now saved for this session."
        } catch (e: Exception) {
            withContext(Dispatchers.Main) { setPairedUi(false) }
            "$paired\nAutomatic connect-port discovery did not finish: ${e.message}. The app will retry discovery when you use an action."
        }
    }

    private suspend fun discoverConnectPort(): String {
        val port = withTimeout(18_000) { discoverLocalAdbPort() }
        withContext(Dispatchers.Main) { connectPortInput.setText(port.toString()) }
        return "Found a Wireless Debugging connect port on this phone: $port"
    }

    private suspend fun stagePayload(inputs: UiInputs): String = withAdb(inputs) { client ->
        val facts = inspectTarget(client)
        command(client, "mkdir -p /data/local/tmp/a '$REMOTE_DIR'")
        val lines = mutableListOf("Target checks passed for ${facts.getValue("model")} / ${facts.getValue("kernel")}.")
        for (payload in PAYLOADS) {
            val localHash = assets.open("payload/${payload.asset}").use(::sha256)
            require(localHash == payload.sha256) { "Packaged ${payload.asset} hash mismatch; refusing to stage." }
            val present = commandAllowFailure(client, "test -e '${payload.path}'")
            if (present.exitCode == 0) {
                val existingHash = parseSha256(command(client, "sha256sum '${payload.path}'"))
                require(existingHash == payload.sha256 ||
                    (payload.asset == "g4d" && existingHash == OLD_G4D_SHA256)) {
                    "Refusing to overwrite an unexpected file at ${payload.path} (SHA-256 $existingHash)."
                }
            }
            val mode = 33261 // regular executable file, 0755
            assets.open("payload/${payload.asset}").use { client.sync.push(it, payload.path, mode) }
            command(client, "chmod 0755 '${payload.path}'")
            val remoteHash = parseSha256(command(client, "sha256sum '${payload.path}'"))
            require(remoteHash == payload.sha256) { "Device copy hash mismatch for ${payload.asset}: $remoteHash" }
            lines += "Staged ${payload.asset} at ${payload.path} (${remoteHash.take(16)}…)."
        }
        getSharedPreferences("manager-state", MODE_PRIVATE).edit()
            .putString("staged_boot_id", facts.getValue("boot_id")).apply()
        withContext(Dispatchers.Main) { setExploitPayloadStaged(true, true) }
        lines.joinToString("\n") + "\nNo exploit was run."
    }

    private suspend fun triggerOnce(inputs: UiInputs): String = withAdb(inputs) { client ->
        val facts = inspectTarget(client)
        val bootId = facts.getValue("boot_id")
        require(bootId.matches(Regex("[0-9a-fA-F-]{36}"))) { "Unexpected boot ID; refusing to trigger." }
        for (payload in PAYLOADS) {
            val remoteHash = parseSha256(command(client, "sha256sum '${payload.path}'"))
            require(remoteHash == payload.sha256) { "Payload missing or changed at ${payload.path}; stage it again." }
        }

        val rootUid = commandAllowFailure(client, "$REMOTE_G4SH -c 'id -u'")
        if (rootUid.exitCode == 0 && rootUid.stdoutText.lineSequence().any { it.trim() == "0" }) {
            error("The one-boot root session is already active. Refusing another exploit attempt.")
        }

        val marker = "$REMOTE_DIR/attempted-$bootId"
        val markerResult = commandAllowFailure(client, "mkdir '$marker'")
        require(markerResult.exitCode == 0) { "This boot was already marked attempted (or the marker could not be created). Refusing to retry." }
        withContext(Dispatchers.Main) {
            triggerExploitButton.visibility = ViewGroup.GONE
            stageExploitButton.visibility = ViewGroup.GONE
            exploitStageStatus.text = "Exploit attempt used for this boot. The app will not retry it."
            exploitStageStatus.visibility = ViewGroup.VISIBLE
        }

        val commandText = "SLIDE_USE_TRACEFS=1 A15_MCAST_FOPS_ROUTE=1 A15_SESSION_ONLY=1 " +
            "A15_MCAST_PRESPRAY_SENDS=144 A15_MCAST_RECLAIM_SENDS=16 '$REMOTE_CANDIDATE'"
        withContext(Dispatchers.Main) { appendLive("\n\nStarting exploit; live output follows:\n") }
        var exitCode: Int? = null
        try {
            client.shellFlow(commandText).collect { chunk ->
                when (chunk) {
                    is ShellChunk.Stdout -> withContext(Dispatchers.Main) { appendLive(chunk.text) }
                    is ShellChunk.Stderr -> withContext(Dispatchers.Main) { appendLive(chunk.text) }
                    is ShellChunk.Exit -> exitCode = chunk.code
                }
            }
        } catch (e: Exception) {
            error("The trigger connection ended after the one-shot marker was created. Do not retry this boot. ${e.message}")
        }
        val verify = try {
            commandAllowFailure(client, "$REMOTE_G4SH -c 'id -u'")
        } catch (e: Exception) {
            error("The trigger returned but ADB disconnected before verification. The attempt marker is retained; do not retry this boot. ${e.message}")
        }
        if (verify.exitCode == 0 && verify.stdoutText.lineSequence().any { it.trim() == "0" }) {
            withContext(Dispatchers.Main) { setExploitStatus(true) }
            "\nOne-boot root session verified (exploit exit ${exitCode ?: "unknown"})."
        } else {
            error("The attempt ended with exit ${exitCode ?: "unknown"}; root was not verified. The marker is retained. Do not retry this boot.")
        }
    }

    private suspend fun cleanStagedFiles(inputs: UiInputs): String = withAdb(inputs) { client ->
        val facts = inspectTarget(client)
        val bootId = facts.getValue("boot_id")
        val rootUid = commandAllowFailure(client, "$REMOTE_G4SH -c 'id -u'")
        if (rootUid.exitCode == 0 && rootUid.stdoutText.lineSequence().any { it.trim() == "0" }) {
            error("The root session is active. Reboot first, then clean the staged files.")
        }
        val currentMarker = "$REMOTE_DIR/attempted-$bootId"
        command(
            client,
            "rm -f '$REMOTE_CANDIDATE' '$REMOTE_G4D' '$REMOTE_G4SH' '$REMOTE_G4D_SU' '$REMOTE_G4SU' " +
                "'$REMOTE_G4MOUNT' '$REMOTE_G4EXEC' '$REMOTE_DEFEX' " +
                "/data/local/tmp/a/g4d.pid /data/local/tmp/a/g4d-su.pid; " +
                "for d in '$REMOTE_DIR'/attempted-*; do " +
                "[ -d \"\$d\" ] && [ \"\$d\" != '$currentMarker' ] && rmdir \"\$d\" 2>/dev/null; " +
                "done; rmdir '$REMOTE_DIR' 2>/dev/null || true",
        )
        getSharedPreferences("manager-state", MODE_PRIVATE).edit().remove("staged_boot_id").apply()
        "Removed the staged candidate, daemon, and client from /data/local/tmp. Any marker for this boot was preserved, so this boot still cannot be retried. Wireless Debugging pairing remains saved."
    }

    private fun openGrantManager() {
        if (busy) return
        val inputs = currentInputs()
        setBusy(true)
        append("Loading app UIDs and current-boot grants…")
        scope.launch {
            var groups: List<AppUidGroup>? = null
            var selected: Set<Int> = emptySet()
            try {
                val snapshot = withContext(Dispatchers.IO) {
                    withAdb(inputs) { client ->
                        val bootId = requireActiveRoot(client)
                        requireSuService(client)
                        val allow = runDefexTarget(
                            client,
                            REMOTE_G4SU,
                            listOf("-c", "if [ -r '$REMOTE_ALLOW' ]; then cat '$REMOTE_ALLOW'; else echo __NO_ALLOWLIST__; fi"),
                        )
                        require(allow.exitCode == 0) { "Could not read the root grant list: ${allow.output}" }
                        val lines = allow.output.lineSequence().map(String::trim).toList()
                        val fileBootId = lines.firstOrNull()?.takeIf { it.startsWith("boot_id=") }
                            ?.removePrefix("boot_id=")
                        val uids = if (fileBootId == bootId) {
                            lines.drop(1).mapNotNull(String::toIntOrNull).filter { it >= 10_000 }.toSet()
                        } else emptySet()
                        withContext(Dispatchers.IO) { appUidGroups() } to uids
                    }
                }
                groups = snapshot.first
                selected = snapshot.second
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                append("ERROR: ${e.message ?: e.javaClass.simpleName}")
            } finally {
                setBusy(false)
            }
            groups?.let { showGrantDialog(it, selected) }
        }
    }

    @Suppress("DEPRECATION")
    private fun appUidGroups(): List<AppUidGroup> {
        val ownApplication = packageManager.getApplicationInfo(packageName, 0)
        val applications = (packageManager.getInstalledApplications(0) + ownApplication)
            .filter { it.uid >= 10_000 }
            .distinctBy { it.packageName }
        return applications.groupBy { it.uid }.map { (uid, members) ->
            val labels = members.mapNotNull { app ->
                runCatching { app.loadLabel(packageManager).toString() }
                    .getOrNull()?.takeIf { it.isNotBlank() }
            }.distinct().sorted()
            val packages = members.map { it.packageName }.sorted()
            val title = "${labels.joinToString(" / ")} · UID $uid\n${packages.joinToString(", ")}"
            AppUidGroup(uid, title)
        }.sortedBy { it.title.substringBefore('\n').lowercase() }
    }

    private fun showGrantDialog(groups: List<AppUidGroup>, initiallySelected: Set<Int>) {
        if (isFinishing || isDestroyed) return
        val selected = initiallySelected.toMutableSet()
        val labels = groups.map { it.title }.toTypedArray()
        val checked = BooleanArray(groups.size) { groups[it].uid in selected }
        AlertDialog.Builder(this)
            .setTitle("Apps allowed to use su")
            .setMultiChoiceItems(labels, checked) { _, index, isChecked ->
                val uid = groups[index].uid
                if (isChecked) selected += uid else selected -= uid
            }
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Continue") { _, _ ->
                confirmGrantSelection(selected.toSet())
            }
            .show()
    }

    private suspend fun applyGrants(inputs: UiInputs, requestedUids: Set<Int>): String = withAdb(inputs) { client ->
        val bootId = requireActiveRoot(client)
        requireSuService(client)
        require(requestedUids.all { it >= 10_000 }) { "Only ordinary app UIDs can be granted." }
        val validUids = withContext(Dispatchers.IO) { appUidGroups().map { it.uid }.toSet() }
        val selected = requestedUids.intersect(validUids).sorted()
        val body = buildString {
            append("boot_id=").append(bootId).append('\n')
            selected.forEach { append(it).append('\n') }
        }.toByteArray(Charsets.US_ASCII)
        val devFs = runDefexTarget(
            client,
            REMOTE_G4SU,
            listOf(
                "-c",
                "awk '\$5 == \"/dev\" { for (i=1; i<=NF; i++) if (\$i == \"-\") { print \$(i+1); exit } }' /proc/self/mountinfo",
            ),
        )
        require(devFs.exitCode == 0 && devFs.output.trim() == "tmpfs") {
            "The grant list must live on /dev tmpfs so it disappears at reboot."
        }
        val ramTemp = "/dev/.ghostlock-grants-${UUID.randomUUID()}"
        val quotedLines = body.toString(Charsets.US_ASCII)
            .lineSequence().filter(String::isNotEmpty).joinToString(" ", transform = ::shellQuote)
        val writeScript = "umask 077; printf '%s\\n' $quotedLines > '$ramTemp' && " +
            "chown 0:0 '$ramTemp' && chmod 0600 '$ramTemp' && mv -f '$ramTemp' '$REMOTE_ALLOW'"
        val result = runDefexTarget(
            client,
            REMOTE_G4SU,
            listOf("-c", writeScript),
        )
        require(result.exitCode == 0) { "Could not atomically install the UID grant list: ${result.output}" }
        val visible = runDefexTarget(client, REMOTE_G4SU, listOf("-c", "head -n 1 '$REMOTE_ALLOW'"))
        require(visible.exitCode == 0 && visible.output.trim() == "boot_id=$bootId") {
            "The app-facing daemon could not read the grant list in its own mount namespace."
        }
        "Applied ${selected.size} UID grant(s) for boot $bootId. New su requests use this list immediately. Packages sharing an allowed UID share the grant."
    }

    private suspend fun prepareRootManager(inputs: UiInputs): String = withAdb(inputs) { client ->
        appendProgress("Checking the active root session…")
        val bootId = requireActiveRoot(client)
        val staged = mutableListOf<String>()
        var suDaemonChanged = false
        var suClientChanged = false
        for (payload in MANAGER_PAYLOADS) {
            appendProgress("Checking ${payload.asset}…")
            val localHash = assets.open("payload/${payload.asset}").use(::sha256)
            require(localHash == payload.sha256) { "Packaged ${payload.asset} hash mismatch; refusing to stage." }
            val exists = rootCommand(client, "test -f '${payload.path}'")
            if (exists.exitCode == 0) {
                val remoteHash = parseSha256(rootCommand(client, "sha256sum '${payload.path}'").output)
                if (remoteHash == payload.sha256) continue
                val knownPreviousHashes = when (payload.asset) {
                    "g4d-su", "g4su", "g4mount" -> PREVIOUS_MANAGER_HASHES.getValue(payload.asset)
                    "g4exec" -> setOf(PREVIOUS_G4EXEC_SHA256)
                    "defex-exec.sh" -> setOf(PREVIOUS_DEFEX_SHA256)
                    else -> emptySet()
                }
                require(remoteHash in knownPreviousHashes) {
                    "Refusing to replace an unexpected file at ${payload.path} (SHA-256 $remoteHash)."
                }
            }
            val temp = "/data/local/tmp/ghostlock-stage-${UUID.randomUUID()}"
            assets.open("payload/${payload.asset}").use { client.sync.push(it, temp, 33261) }
            val moved = rootCommand(
                client,
                "test -f '$temp' && test ! -L '$temp' && chown 0:0 '$temp' && chmod 0755 '$temp' && mv -f '$temp' '${payload.path}'",
            )
            require(moved.exitCode == 0) { "Could not stage ${payload.asset}: ${moved.output}" }
            val remoteHash = parseSha256(rootCommand(client, "sha256sum '${payload.path}'").output)
            require(remoteHash == payload.sha256) { "Device copy hash mismatch for ${payload.asset}: $remoteHash" }
            staged += payload.asset
            if (payload.asset == "g4d-su") suDaemonChanged = true
            if (payload.asset == "g4su") suClientChanged = true
        }

        if (suDaemonChanged) {
            appendProgress("Restarting the app-facing su service for the updated protocol…")
            val stopped = rootCommand(
                client,
                "pid=\$(cat '$REMOTE_SU_PID' 2>/dev/null); " +
                    "case \"\$pid\" in ''|*[!0-9]*) ;; *) " +
                    "comm=\$(cat \"/proc/\$pid/comm\" 2>/dev/null); " +
                    "if [ \"\$comm\" = g4d ] || [ \"\$comm\" = g4d-su ]; then " +
                    "kill \"\$pid\" || true; sleep 1; fi ;; esac; " +
                    "rm -f '$REMOTE_SU_PID'",
            )
            require(stopped.exitCode == 0) { "Could not stop the old app-facing service: ${stopped.output}" }
        }

        if (suClientChanged) {
            appendProgress("Refreshing the live app su entrypoint…")
            val overlay = runDefexTarget(client, REMOTE_G4MOUNT, listOf("status"))
            require(overlay.exitCode == 0) { "Could not inspect the live su entrypoint: ${overlay.output}" }
            if (!overlay.output.contains("no su overlay.")) {
                val removed = runDefexTarget(client, REMOTE_G4MOUNT, listOf("remove"))
                require(removed.exitCode == 0) { "Could not remove the old su entrypoint: ${removed.output}" }
                val installed = runDefexTarget(client, REMOTE_G4MOUNT, listOf("install"))
                require(installed.exitCode == 0) { "Could not refresh the su entrypoint: ${installed.output}" }
            }
        }

        appendProgress("Checking the app-facing su service…")
        var probe = runDefexTarget(client, REMOTE_G4SU, listOf("-c", "id -u"))
        if (probe.exitCode != 0 || probe.output.lineSequence().none { it.trim() == "0" }) {
            appendProgress("Starting the app-facing root service…")
            val launch = rootCommand(client, "/system/bin/sh '$REMOTE_DEFEX' '$REMOTE_G4D_SU'")
            require(launch.exitCode == 0) { "Could not start the app-facing root service: ${launch.output}" }
            var started = false
            var attempt = 0
            while (attempt < 12 && !started) {
                appendProgress("Waiting for the app-facing su service (${attempt + 1}/12)…")
                Thread.sleep(250)
                probe = runDefexTarget(client, REMOTE_G4SU, listOf("-c", "id -u"))
                if (probe.exitCode == 0 && probe.output.lineSequence().any { it.trim() == "0" }) {
                    started = true
                }
                attempt++
            }
            require(started) {
                "The shell root session is alive, but the app-facing su service did not respond through the DEFEX-safe launcher. Last response: ${probe.output}"
            }
        }
        getSharedPreferences("manager-state", MODE_PRIVATE).edit()
            .putString("manager_boot_id", bootId).apply()
        withContext(Dispatchers.Main) { setManagerPrepared(true) }
        val changed = if (staged.isEmpty()) "All manager tools were already staged." else "Staged: ${staged.joinToString()} ."
        "$changed ADB-side root service is ready for boot $bootId. App-process su launch still needs its own check. No exploit was run."
    }

    private suspend fun manageSuOverlay(inputs: UiInputs, operation: String): String = withAdb(inputs) { client ->
        requireActiveRoot(client)
        val ready = rootCommand(
            client,
            "test -x '$REMOTE_G4MOUNT' && test -x '$REMOTE_G4EXEC' && test -r '$REMOTE_DEFEX'",
        )
        require(ready.exitCode == 0) { "Tap ‘Prepare root manager for this boot’ first." }
        if (operation == "install") {
            val probe = runDefexTarget(client, REMOTE_G4SU, listOf("-c", "id -u"))
            require(probe.exitCode == 0 && probe.output.lineSequence().any { it.trim() == "0" }) {
                "The app-facing root service is not ready. Prepare the root manager first."
            }
        }
        val result = runDefexTarget(client, REMOTE_G4MOUNT, listOf(operation))
        require(result.exitCode == 0) { "g4mount $operation failed: ${result.output}" }
        result.output.ifBlank { "g4mount $operation completed." }
    }

    private suspend fun managerStatus(inputs: UiInputs): String = withAdb(inputs) { client ->
        val bootId = requireActiveRoot(client)
        val ready = rootCommand(
            client,
            "test -x '$REMOTE_G4MOUNT' && test -x '$REMOTE_G4SU' && test -x '$REMOTE_G4EXEC' && test -r '$REMOTE_DEFEX'",
        )
        if (ready.exitCode != 0) return@withAdb "Root session is active for boot $bootId. Root manager tools are not prepared."
        val allow = runDefexTarget(
            client,
            REMOTE_G4SU,
            listOf("-c", "if [ -r '$REMOTE_ALLOW' ]; then cat '$REMOTE_ALLOW'; else echo __NO_ALLOWLIST__; fi"),
        )
        val lines = allow.output.lineSequence().map(String::trim).toList()
        val allowBoot = lines.firstOrNull()?.removePrefix("boot_id=")
        val grantedCount = if (allowBoot == bootId) lines.drop(1).count { it.toIntOrNull() != null } else 0
        val service = runDefexTarget(client, REMOTE_G4SU, listOf("-c", "id -u"))
        val serviceReady = service.exitCode == 0 && service.output.lineSequence().any { it.trim() == "0" }
        val mounts = runDefexTarget(client, REMOTE_G4MOUNT, listOf("status"))
        "Boot ID: $bootId\nADB-side root daemon: ${if (serviceReady) "ready" else "not responding"}\n" +
            "Current-boot UID grants: $grantedCount\nZygote su overlay:\n${mounts.output.ifBlank { "status unavailable" }}"
    }

    private suspend fun testCurrentAppSu(): String {
        val shell = runAppProcess("/system/bin/sh", "-c", "echo GHOSTSHELL_EXEC_OK")
        require(shell.first == 0 && shell.second.contains("GHOSTSHELL_EXEC_OK")) {
            "App shell launch failed (exit ${shell.first}): ${shell.second.trim()}"
        }
        val version = runAppProcess("/system/bin/su", "-v")
        require(version.first == 0) {
            "App could not execute su -v (exit ${version.first}): ${version.second.trim()}"
        }
        val root = runAppProcess("/system/bin/su", "-c", "id -u")
        require(root.first == 0 && root.second.lineSequence().any { it.trim() == "0" }) {
            "su launched, but its root request failed (exit ${root.first}): ${root.second.trim()}\nGrant the GhostSlop app UID, install the su overlay, then force-stop and reopen this app."
        }
        return "App shell and su launch succeeded; g4d returned UID 0."
    }

    private fun runAppProcess(vararg argv: String): Pair<Int, String> {
        val process = try {
            ProcessBuilder(*argv).redirectErrorStream(true).start()
        } catch (e: Exception) {
            throw IllegalStateException("Cannot start ${argv.first()}: ${e.message}", e)
        }
        if (!process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
            process.destroyForcibly()
            throw IllegalStateException("${argv.first()} did not finish within 10 seconds.")
        }
        val output = process.inputStream.bufferedReader().use { it.readText().take(4000) }
        return process.exitValue() to output
    }

    private suspend fun requireActiveRoot(client: AdbClient): String {
        val model = command(client, "getprop ro.product.model")
        require(model == EXPECTED_MODEL) { "Wrong model: expected $EXPECTED_MODEL, found $model." }
        val kernel = command(client, "uname -r")
        require(kernel == EXPECTED_KERNEL) { "Wrong kernel: expected $EXPECTED_KERNEL, found $kernel." }
        val fingerprint = command(client, "getprop ro.build.fingerprint")
        require(fingerprint == EXPECTED_FINGERPRINT) {
            "Wrong build fingerprint: expected $EXPECTED_FINGERPRINT, found $fingerprint."
        }
        val bootloader = command(client, "getprop ro.bootloader")
        require(bootloader == EXPECTED_BOOTLOADER) {
            "Wrong bootloader build: expected $EXPECTED_BOOTLOADER, found $bootloader."
        }
        val bootId = command(client, "cat /proc/sys/kernel/random/boot_id")
        require(bootId.matches(Regex("[0-9a-fA-F-]{36}"))) { "Could not read a valid current boot ID." }
        val root = rootCommand(client, "id -u")
        require(root.exitCode == 0 && root.output.lineSequence().any { it.trim() == "0" }) {
            "The one-boot root session is not active or g4sh is unavailable."
        }
        return bootId
    }

    private suspend fun requireSuService(client: AdbClient) {
        val files = rootCommand(
            client,
            "test -x '$REMOTE_G4SU' && test -x '$REMOTE_G4EXEC' && test -r '$REMOTE_DEFEX'",
        )
        require(files.exitCode == 0) { "Tap ‘Prepare root manager for this boot’ first." }
        val probe = runDefexTarget(client, REMOTE_G4SU, listOf("-c", "id -u"))
        require(probe.exitCode == 0 && probe.output.lineSequence().any { it.trim() == "0" }) {
            "The app-facing root service is not responding. Prepare the root manager first."
        }
    }

    private suspend fun runDefexTarget(client: AdbClient, target: String, args: List<String>): RootResult {
        val command = buildList {
            add("/system/bin/sh")
            add(REMOTE_DEFEX)
            add(target)
            addAll(args)
        }.joinToString(" ") { shellQuote(it) }
        return rootCommand(client, command)
    }

    private suspend fun rootCommand(client: AdbClient, script: String): RootResult {
        val nonce = UUID.randomUUID().toString().replace("-", "")
        val begin = "__GHOSTLOCK_BEGIN_${nonce}__"
        val end = "__GHOSTLOCK_RC_${nonce}__"
        val dollar = '$'
        val wrapped = "printf '\\n%s\\n' '$begin'; $script; rc=${dollar}?; " +
            "printf '\\n%s=%d\\n' '$end' \"${dollar}rc\""
        val shellCommand = "$REMOTE_G4SH -c ${shellQuote(wrapped)}"
        val result = try {
            withTimeout(ROOT_COMMAND_TIMEOUT_MS) { client.shell(shellCommand) }
        } catch (e: TimeoutCancellationException) {
            throw IllegalStateException(
                "Root command timed out after ${ROOT_COMMAND_TIMEOUT_MS / 1000}s: ${script.take(120)}",
                e,
            )
        }
        val lines = result.stdoutText.lineSequence().map { it.trimEnd('\r') }.toList()
        val start = lines.indexOf(begin)
        val endLine = lines.indexOfFirst { it.startsWith("$end=") }
        if (start < 0 || endLine <= start) {
            error("Root command did not return its status marker. ${result.stderrText.trim()} ${result.stdoutText.takeLast(1200)}")
        }
        val exitCode = lines[endLine].substringAfter('=').toIntOrNull()
            ?: error("Root command returned an invalid status marker.")
        return RootResult(lines.subList(start + 1, endLine).joinToString("\n").trim(), exitCode)
    }

    private fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    private suspend fun inspectTarget(client: AdbClient): Map<String, String> {
        val facts = linkedMapOf(
            "model" to command(client, "getprop ro.product.model"),
            "kernel" to command(client, "uname -r"),
            "fingerprint" to command(client, "getprop ro.build.fingerprint"),
            "bootloader" to command(client, "getprop ro.bootloader"),
            "boot_completed" to command(client, "getprop sys.boot_completed"),
            "selinux" to command(client, "getenforce"),
            "shell_uid" to command(client, "id -u"),
            "shell_context" to command(client, "id -Z"),
            "boot_id" to command(client, "cat /proc/sys/kernel/random/boot_id"),
        )
        require(facts["model"] == EXPECTED_MODEL) { "Wrong model: expected $EXPECTED_MODEL, found ${facts["model"]}." }
        require(facts["kernel"] == EXPECTED_KERNEL) { "Wrong kernel: expected $EXPECTED_KERNEL, found ${facts["kernel"]}." }
        require(facts["fingerprint"] == EXPECTED_FINGERPRINT) {
            "Wrong build fingerprint: expected $EXPECTED_FINGERPRINT, found ${facts["fingerprint"]}."
        }
        require(facts["bootloader"] == EXPECTED_BOOTLOADER) {
            "Wrong bootloader build: expected $EXPECTED_BOOTLOADER, found ${facts["bootloader"]}."
        }
        require(facts["boot_completed"] == "1" && facts["selinux"] == "Enforcing" &&
            facts["shell_uid"] == "2000" && facts["shell_context"] == "u:r:shell:s0") {
            "ADB is not in the expected clean shell state: ${facts.filterKeys { it in setOf("boot_completed", "selinux", "shell_uid", "shell_context") }}"
        }
        return facts
    }

    private suspend fun <T> withAdb(inputs: UiInputs, block: suspend (AdbClient) -> T): T {
        val guid = getSharedPreferences("adb-pairing", MODE_PRIVATE).getString("device_guid", null)
        require(!guid.isNullOrBlank()) { "Pair this app with Wireless Debugging first." }
        val port = if (inputs.connectPort.isBlank()) {
            withTimeout(18_000) { discoverLocalAdbPort() }
        } else {
            inputs.connectPort.toIntOrNull()?.takeIf { it in 1..65535 }
                ?: error("Enter a valid Wireless Debugging connect port or clear the override for automatic discovery.")
        }
        val keys = keyProvider()
        val identity = buildPairingIdentity(keys)
        val client = AdbClient.connectTls(ADB_HOST, port, keys, identity)
        try {
            val uid = command(client, "id -u")
            require(uid == "2000") { "ADB connection is not shell UID 2000 (got $uid)." }
            return block(client)
        } finally {
            client.close()
        }
    }

    private fun keyProvider() = FileKeyProvider(
        File(filesDir, "adb/adbkey"),
        identityComment = "GhostLockBootstrap",
    )

    private suspend fun command(client: AdbClient, command: String): String {
        val result = client.shell(command)
        if (!result.isSuccess) {
            error("Command failed ($command): ${result.stderrText.trim()}".trim())
        }
        return result.stdoutText.trim()
    }

    private suspend fun commandAllowFailure(client: AdbClient, command: String) = client.shell(command)

    private fun parseSha256(line: String): String {
        val value = line.trim().substringBefore(' ').lowercase()
        require(value.matches(Regex("[0-9a-f]{64}"))) { "Could not read SHA-256 from: $line" }
        return value
    }

    private fun sha256(input: java.io.InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private suspend fun discoverLocalAdbPort(): Int = suspendCancellableCoroutine { continuation ->
        val manager = getSystemService(NSD_SERVICE) as NsdManager
        val pending = ArrayDeque<NsdServiceInfo>()
        val lock = (getSystemService(WIFI_SERVICE) as WifiManager).createMulticastLock("ghostslop-adb-discovery").apply {
            setReferenceCounted(false)
        }
        val cleaned = AtomicBoolean(false)
        var started = false
        var resolving = false
        lateinit var listener: NsdManager.DiscoveryListener

        fun cleanup() {
            if (!cleaned.compareAndSet(false, true)) return
            if (started) runCatching { manager.stopServiceDiscovery(listener) }
            if (lock.isHeld) runCatching { lock.release() }
        }

        lateinit var resolveNext: () -> Unit
        resolveNext = {
            if (continuation.isActive && !resolving && pending.isNotEmpty()) {
                resolving = true
                val service = pending.removeFirst()
                manager.resolveService(service, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                        resolving = false
                        resolveNext()
                    }

                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        resolving = false
                        val address = serviceInfo.host?.hostAddress?.substringBefore('%')
                        if (serviceInfo.port in 1..65535 && address in localAddresses()) {
                            cleanup()
                            if (continuation.isActive) continuation.resume(serviceInfo.port)
                        } else {
                            resolveNext()
                        }
                    }
                })
            }
        }

        listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (serviceInfo.serviceType?.contains("_adb-tls-connect._tcp") == true) {
                    pending.addLast(serviceInfo)
                    resolveNext()
                }
            }
            override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
            override fun onDiscoveryStopped(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                cleanup()
                if (continuation.isActive) continuation.resumeWithException(IllegalStateException("mDNS discovery failed: $errorCode"))
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
        }

        continuation.invokeOnCancellation { cleanup() }
        try {
            lock.acquire()
            manager.discoverServices("_adb-tls-connect._tcp", NsdManager.PROTOCOL_DNS_SD, listener)
            started = true
        } catch (e: Exception) {
            cleanup()
            if (continuation.isActive) continuation.resumeWithException(e)
        }
    }

    private fun localAddresses(): Set<String> {
        val addresses = mutableSetOf("127.0.0.1", "::1")
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return addresses
        while (interfaces.hasMoreElements()) {
            val networkInterface = interfaces.nextElement()
            val inetAddresses = networkInterface.inetAddresses
            while (inetAddresses.hasMoreElements()) {
                val address: InetAddress = inetAddresses.nextElement()
                if (!address.isLoopbackAddress) addresses += address.hostAddress.orEmpty().substringBefore('%')
            }
        }
        return addresses
    }

    private fun append(message: String) {
        appendLive("\n\n$message")
    }

    private suspend fun appendProgress(message: String) {
        withContext(Dispatchers.Main) { appendLive("\n$message") }
    }

    private fun appendLive(message: String) {
        if (!::output.isInitialized) return
        output.append(message)
        if (output.length() > 60_000) {
            output.text = "[Earlier log text trimmed]\n" + output.text.takeLast(45_000)
        }
        logScrollView.post { logScrollView.fullScroll(ScrollView.FOCUS_DOWN) }
        scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
