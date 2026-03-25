<?php
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

require_once __DIR__ . '/includes/session_init.php';
require_once __DIR__ . '/includes/config_cf.php';

header('Cache-Control: private, no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

/* ─────────────────────────────── HELPERS ─────────────────────────────── */

function jsonOut(int $code, array $payload): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function isAjax(): bool {
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower((string)$_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function envGet(string $key, string $default = ''): string {
    static $cache = null;
    if ($cache === null) {
        $cache = [];
        $envFile = '/etc/teth-ws/.env';
        if (is_file($envFile) && is_readable($envFile)) {
            $lines = @file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines ?: [] as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#')) continue;
                if (str_starts_with($line, 'export ')) $line = trim(substr($line, 7));
                $pos = strpos($line, '=');
                if ($pos === false) continue;
                $k = trim(substr($line, 0, $pos));
                $v = trim(substr($line, $pos + 1));
                if ((str_starts_with($v, '"') && str_ends_with($v, '"')) ||
                    (str_starts_with($v, "'") && str_ends_with($v, "'"))) {
                    $v = substr($v, 1, -1);
                }
                if ($k !== '') $cache[$k] = $v;
            }
        }
    }
    $v = (string)($cache[$key] ?? '');
    return ($v !== '') ? $v : $default;
}

/* ─────────────────────────────── SESSION / AUTH ─────────────────────── */

$user_id = (int)($_SESSION['user_id'] ?? 0);
if ($user_id <= 0) {
    if (isAjax()) jsonOut(401, ['ok' => false, 'redirect' => 'connexion.php']);
    header('Location: connexion.php');
    exit;
}

$IDLE_TIMEOUT = 1800;
$now = time();
if (!isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = $now;
} else {
    if (($now - (int)$_SESSION['last_activity']) > $IDLE_TIMEOUT) {
        session_unset();
        session_destroy();
        if (isAjax()) jsonOut(401, ['ok' => false, 'redirect' => 'connexion.php']);
        header('Location: connexion.php');
        exit;
    }
    $_SESSION['last_activity'] = $now;
}

if (empty($_SESSION['csrf_finance'])) {
    $_SESSION['csrf_finance'] = bin2hex(random_bytes(32));
}
$CSRF = (string)$_SESSION['csrf_finance'];

function csrfCheckOrFail(): void {
    $sess = (string)($_SESSION['csrf_finance'] ?? '');
    $in   = (string)($_POST['csrf']            ?? '');
    if ($sess === '' || $in === '' || !hash_equals($sess, $in)) {
        jsonOut(403, ['ok' => false, 'message' => 'Session expirée. Rechargez la page.', 'reload' => true]);
    }
}

/* ─────────────────────────────── CONSTANTES ─────────────────────────── */

define('FLEXPAIE_MM_PAYMENT_URL', 'https://backend.flexpay.cd/api/rest/v1/paymentService');
define('FLEXPAIE_PAYOUT_URL',     'https://backend.flexpay.cd/api/rest/v1/merchantPayOutService');
define('FLEXPAIE_CHECK_BASE',     'https://backend.flexpay.cd/api/rest/v1/check/');
define('DEFAULT_DEVISE',          'CDF');
define('MIN_DEPOT_FC',            1000);
define('MIN_RETRAIT_FC',          5000);
define('MAX_DEPOT_FC',            2000000);
define('MAX_RETRAIT_FC',          2000000);
define('PENDING_TTL_SECONDS',     300);
define('MOTIF_DEPOT',             'Depot TETH PAY');
define('MOTIF_RETRAIT',           'Retrait TETH PAY');

$flexpaieMerchant    = envGet('FLEXPAIE_MERCHANT', 'TETH');
$devise              = envGet('FLEXPAIE_DEVISE', DEFAULT_DEVISE);
$flexpaieCallbackUrl = envGet('FLEXPAIE_CALLBACK_URL', '');

function flexpaieBearer(): string { return envGet('FLEXPAIE_BEARER_TOKEN', ''); }

/* ─────────────────────────────── DB ─────────────────────────────────── */

function dbOrFail(): mysqli {
    $db = getDBConnection();
    if (!($db instanceof mysqli)) jsonOut(500, ['ok' => false, 'message' => 'Service indisponible.']);
    $db->set_charset('utf8mb4');
    return $db;
}

function loadUser(mysqli $db, int $userId): array {
    $st = $db->prepare(
        "SELECT id, telephone, surnom_de_jeux, ville, actif,
         COALESCE(solde_depot,0)  solde_depot,
         COALESCE(solde_gain,0)   solde_gain,
         COALESCE(portefeuille,0) portefeuille,
         motdepasse,
         COALESCE(tentatives_echouees,0)       tentatives_echouees,
         COALESCE(compte_verrouille_jusque,0)  compte_verrouille_jusque,
         COALESCE(agent_fail_streak,0)         agent_fail_streak,
         COALESCE(agent_locked_until,0)        agent_locked_until
         FROM utilisateurs WHERE id = ? LIMIT 1"
    );
    if (!$st) return [];
    $st->bind_param('i', $userId);
    $st->execute();
    $u = $st->get_result()->fetch_assoc() ?: [];
    $st->close();
    return $u;
}

function addNotif(mysqli $db, int $userId, string $type, string $msg): void {
    $st = $db->prepare(
        "INSERT INTO notifications (user_id, type, message, lu, created_at)
         VALUES (?, ?, ?, 0, NOW())"
    );
    if (!$st) return;
    $st->bind_param('iss', $userId, $type, $msg);
    $st->execute();
    $st->close();
}

/* ─────────────────────────────── UTILITAIRES ────────────────────────── */

function flexpaieRef20(): string {
    return strtoupper(substr(bin2hex(random_bytes(10)), 0, 20));
}

function parseAmount(string $raw): float {
    $v = (float)preg_replace('/[^\d.]/', '', str_replace(',', '.', $raw));
    return round($v, 2);
}

function normalizeTel(string $t): string {
    $t = preg_replace('/[^\d]/', '', $t);
    if (strlen($t) === 9) $t = '243' . $t;
    if (str_starts_with($t, '0') && strlen($t) === 10) $t = '243' . substr($t, 1);
    return $t;
}

/* ─────────────────────────────── FLEXPAIE CALLS ────────────────────── */

function flexpaieCall(string $url, array $body): array {
    $bearer = flexpaieBearer();
    if ($bearer === '') return ['code' => 1, 'message' => 'Token FlexPay manquant.'];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($body),
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $bearer,
            'Content-Type: application/json',
            'Accept: application/json',
        ],
    ]);
    $raw  = curl_exec($ch);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($raw === false) return ['code' => 1, 'message' => 'Erreur réseau: ' . $err];
    $data = json_decode((string)$raw, true);
    return is_array($data) ? $data : ['code' => 1, 'message' => 'Réponse invalide de FlexPay.'];
}

function flexpaieGet(string $orderRef): array {
    $bearer = flexpaieBearer();
    if ($bearer === '') return ['code' => 1, 'message' => 'Token FlexPay manquant.'];
    $url = FLEXPAIE_CHECK_BASE . rawurlencode($orderRef);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $bearer,
            'Accept: application/json',
        ],
    ]);
    $raw = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($raw === false) return ['code' => 1, 'message' => 'Erreur réseau: ' . $err];
    $data = json_decode((string)$raw, true);
    return is_array($data) ? $data : ['code' => 1, 'message' => 'Réponse invalide de FlexPay.'];
}

/* ─────────────────────────────── VERROU MOT DE PASSE ACTION ─────────── */

function verifyActionPasswordOrFail(mysqli $db, int $userId, string $pwd): void {
    $u = loadUser($db, $userId);
    if (empty($u)) jsonOut(403, ['ok' => false, 'message' => 'Utilisateur introuvable.']);
    $lockUntil = (int)($u['compte_verrouille_jusque'] ?? 0);
    if ($lockUntil > time()) {
        $wait = ceil(($lockUntil - time()) / 60);
        jsonOut(403, ['ok' => false, 'message' => "Compte verrouillé. Réessayez dans {$wait} min."]);
    }
    if (!password_verify($pwd, (string)($u['motdepasse'] ?? ''))) {
        $fails = (int)($u['tentatives_echouees'] ?? 0) + 1;
        if ($fails >= 5) {
            $until = time() + 900;
            $stl = $db->prepare("UPDATE utilisateurs SET tentatives_echouees=0, compte_verrouille_jusque=? WHERE id=?");
            $stl->bind_param('ii', $until, $userId); $stl->execute(); $stl->close();
            jsonOut(403, ['ok' => false, 'message' => 'Trop de tentatives. Compte verrouillé 15 min.']);
        }
        $stf = $db->prepare("UPDATE utilisateurs SET tentatives_echouees=? WHERE id=?");
        $stf->bind_param('ii', $fails, $userId); $stf->execute(); $stf->close();
        $restant = 5 - $fails;
        jsonOut(403, ['ok' => false, 'message' => "Mot de passe incorrect. {$restant} tentative(s) restante(s)."]);
    }
    $str = $db->prepare("UPDATE utilisateurs SET tentatives_echouees=0, compte_verrouille_jusque=0 WHERE id=?");
    $str->bind_param('i', $userId); $str->execute(); $str->close();
}

/* ═══════════════════════════════ AJAX ══════════════════════════════════ */

$action = (string)($_POST['action'] ?? $_GET['action'] ?? '');

if (isAjax() && $action !== '') {

    /* ── SOLDE ── */
    if ($action === 'get_solde') {
        $db = dbOrFail();
        $u  = loadUser($db, $user_id);
        $db->close();
        if (empty($u)) jsonOut(404, ['ok' => false, 'message' => 'Utilisateur introuvable.']);
        jsonOut(200, [
            'ok'           => true,
            'solde_depot'  => (float)$u['solde_depot'],
            'solde_gain'   => (float)$u['solde_gain'],
            'portefeuille' => (float)$u['portefeuille'],
        ]);
    }

    /* ── HISTORIQUE ── */
    if ($action === 'get_history') {
        $db    = dbOrFail();
        $limit = min((int)($_GET['limit'] ?? 20), 50);
        $page  = max((int)($_GET['page']  ?? 1), 1);
        $offset = ($page - 1) * $limit;
        $st = $db->prepare(
            "SELECT id, type, montant, devise, statut, reference_externe, telephone,
                    DATE_FORMAT(created_at,'%d/%m/%Y %H:%i') created_fmt
             FROM transactions_finance
             WHERE user_id = ?
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?"
        );
        if (!$st) jsonOut(500, ['ok' => false, 'message' => 'Erreur requête.']);
        $st->bind_param('iii', $user_id, $limit, $offset);
        $st->execute();
        $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);
        $st->close();
        $stc = $db->prepare("SELECT COUNT(*) cnt FROM transactions_finance WHERE user_id = ?");
        $stc->bind_param('i', $user_id);
        $stc->execute();
        $total = (int)($stc->get_result()->fetch_assoc()['cnt'] ?? 0);
        $stc->close();
        $db->close();
        jsonOut(200, ['ok' => true, 'rows' => $rows, 'total' => $total, 'page' => $page, 'limit' => $limit]);
    }

    /* ── INIT DÉPÔT ── */
    if ($action === 'init_depot') {
        csrfCheckOrFail();
        $db  = dbOrFail();
        $u   = loadUser($db, $user_id);
        if (empty($u) || !(int)$u['actif']) jsonOut(403, ['ok' => false, 'message' => 'Compte inactif.']);

        $montant = parseAmount((string)($_POST['montant'] ?? ''));
        $tel     = normalizeTel((string)($_POST['telephone'] ?? $u['telephone'] ?? ''));
        $pwd     = (string)($_POST['pwd'] ?? '');

        if ($montant < MIN_DEPOT_FC) jsonOut(400, ['ok' => false, 'message' => 'Montant minimum: ' . number_format(MIN_DEPOT_FC, 0, ',', ' ') . ' ' . DEFAULT_DEVISE]);
        if ($montant > MAX_DEPOT_FC) jsonOut(400, ['ok' => false, 'message' => 'Montant maximum: ' . number_format(MAX_DEPOT_FC, 0, ',', ' ') . ' ' . DEFAULT_DEVISE]);
        if (strlen($tel) < 9)        jsonOut(400, ['ok' => false, 'message' => 'Numéro de téléphone invalide.']);
        if ($pwd === '')             jsonOut(400, ['ok' => false, 'message' => 'Mot de passe requis.']);

        verifyActionPasswordOrFail($db, $user_id, $pwd);

        $ref     = flexpaieRef20();
        $merchant = envGet('FLEXPAIE_MERCHANT', 'TETH');
        $deviseV  = envGet('FLEXPAIE_DEVISE', DEFAULT_DEVISE);
        $cbUrl    = envGet('FLEXPAIE_CALLBACK_URL', '');

        $body = [
            'merchant'    => $merchant,
            'type'        => 1,
            'phone'       => $tel,
            'reference'   => $ref,
            'amount'      => (string)(int)$montant,
            'currency'    => $deviseV,
            'description' => MOTIF_DEPOT,
            'callback_url'=> $cbUrl,
        ];

        $resp = flexpaieCall(FLEXPAIE_MM_PAYMENT_URL, $body);
        $fpCode = (int)($resp['code'] ?? 1);

        $st = $db->prepare(
            "INSERT INTO transactions_finance
             (user_id, type, montant, devise, telephone, reference_externe,
              statut, flexpaie_code, flexpaie_message, created_at, updated_at)
             VALUES (?, 'depot', ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())"
        );
        $statut  = ($fpCode === 0) ? 'pending' : 'echec';
        $fpMsg   = (string)($resp['message'] ?? '');
        $st->bind_param('idssssss', $user_id, $montant, $deviseV, $tel, $ref, $statut, $fpCode, $fpMsg);
        $st->execute();
        $txId = (int)$db->insert_id;
        $st->close();
        $db->close();

        if ($fpCode !== 0) {
            jsonOut(502, ['ok' => false, 'message' => 'FlexPay: ' . ($resp['message'] ?? 'Erreur inconnue.'), 'ref' => $ref]);
        }

        jsonOut(200, [
            'ok'      => true,
            'message' => 'Demande envoyée. Validez le paiement sur votre téléphone.',
            'ref'     => $ref,
            'tx_id'   => $txId,
        ]);
    }

    /* ── INIT RETRAIT ── */
    if ($action === 'init_retrait') {
        csrfCheckOrFail();
        $db  = dbOrFail();
        $u   = loadUser($db, $user_id);
        if (empty($u) || !(int)$u['actif']) jsonOut(403, ['ok' => false, 'message' => 'Compte inactif.']);

        $montant = parseAmount((string)($_POST['montant'] ?? ''));
        $tel     = normalizeTel((string)($_POST['telephone'] ?? $u['telephone'] ?? ''));
        $source  = (string)($_POST['source'] ?? 'solde_depot');
        $pwd     = (string)($_POST['pwd'] ?? '');

        if (!in_array($source, ['solde_depot', 'solde_gain', 'portefeuille'], true)) {
            jsonOut(400, ['ok' => false, 'message' => 'Source invalide.']);
        }
        if ($montant < MIN_RETRAIT_FC) jsonOut(400, ['ok' => false, 'message' => 'Montant minimum: ' . number_format(MIN_RETRAIT_FC, 0, ',', ' ') . ' ' . DEFAULT_DEVISE]);
        if ($montant > MAX_RETRAIT_FC) jsonOut(400, ['ok' => false, 'message' => 'Montant maximum: ' . number_format(MAX_RETRAIT_FC, 0, ',', ' ') . ' ' . DEFAULT_DEVISE]);
        if (strlen($tel) < 9)         jsonOut(400, ['ok' => false, 'message' => 'Numéro de téléphone invalide.']);
        if ($pwd === '')              jsonOut(400, ['ok' => false, 'message' => 'Mot de passe requis.']);

        verifyActionPasswordOrFail($db, $user_id, $pwd);

        $solde = (float)($u[$source] ?? 0);
        if ($montant > $solde) {
            jsonOut(400, ['ok' => false, 'message' => 'Solde insuffisant. Disponible: ' . number_format($solde, 0, ',', ' ') . ' ' . DEFAULT_DEVISE]);
        }

        $db->begin_transaction();
        $stlk = $db->prepare("SELECT id FROM utilisateurs WHERE id = ? LIMIT 1 FOR UPDATE");
        $stlk->bind_param('i', $user_id); $stlk->execute(); $stlk->close();
        $lock = true;

        $u2 = loadUser($db, $user_id);
        if ((float)($u2[$source] ?? 0) < $montant) {
            $db->rollback(); $db->close();
            jsonOut(400, ['ok' => false, 'message' => 'Solde insuffisant (vérification).']);
        }

        $ref      = flexpaieRef20();
        $merchant = envGet('FLEXPAIE_MERCHANT', 'TETH');
        $deviseV  = envGet('FLEXPAIE_DEVISE', DEFAULT_DEVISE);

        $body = [
            'merchant'    => $merchant,
            'type'        => 2,
            'phone'       => $tel,
            'reference'   => $ref,
            'amount'      => (string)(int)$montant,
            'currency'    => $deviseV,
            'description' => MOTIF_RETRAIT,
        ];

        $resp   = flexpaieCall(FLEXPAIE_PAYOUT_URL, $body);
        $fpCode = (int)($resp['code'] ?? 1);

        if ($fpCode !== 0) {
            $db->rollback(); $db->close();
            jsonOut(502, ['ok' => false, 'message' => 'FlexPay: ' . ($resp['message'] ?? 'Erreur inconnue.'), 'ref' => $ref]);
        }

        $allowedSources = ['solde_depot', 'solde_gain', 'portefeuille'];
        if (!in_array($source, $allowedSources, true)) {
            $db->rollback(); $db->close();
            jsonOut(400, ['ok' => false, 'message' => 'Source invalide.']);
        }
        $stbal = $db->prepare("UPDATE utilisateurs SET `{$source}` = `{$source}` - ? WHERE id = ?");
        $stbal->bind_param('di', $montant, $user_id); $stbal->execute(); $stbal->close();

        $fpMsg  = (string)($resp['message'] ?? '');
        $statut = 'pending';
        $st = $db->prepare(
            "INSERT INTO transactions_finance
             (user_id, type, montant, devise, telephone, reference_externe,
              statut, flexpaie_code, flexpaie_message, source_solde, created_at, updated_at)
             VALUES (?, 'retrait', ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())"
        );
        $st->bind_param('idsssssss', $user_id, $montant, $deviseV, $tel, $ref, $statut, $fpCode, $fpMsg, $source);
        $st->execute();
        $txId = (int)$db->insert_id;
        $st->close();

        addNotif($db, $user_id, 'retrait', "Retrait {$montant} {$deviseV} initié (réf: {$ref}).");
        $db->commit();
        $db->close();

        jsonOut(200, [
            'ok'      => true,
            'message' => 'Retrait initié. Vérifiez votre téléphone.',
            'ref'     => $ref,
            'tx_id'   => $txId,
        ]);
    }

    /* ── CHECK STATUS ── */
    if ($action === 'check_status') {
        $ref  = preg_replace('/[^A-Z0-9\-_]/', '', strtoupper((string)($_GET['ref'] ?? $_POST['ref'] ?? '')));
        $txId = (int)($_GET['tx_id'] ?? $_POST['tx_id'] ?? 0);
        if ($ref === '') jsonOut(400, ['ok' => false, 'message' => 'Référence manquante.']);

        $db = dbOrFail();

        $st = $db->prepare(
            "SELECT id, type, montant, devise, statut, source_solde, user_id
             FROM transactions_finance
             WHERE reference_externe = ? AND user_id = ? LIMIT 1"
        );
        $st->bind_param('si', $ref, $user_id);
        $st->execute();
        $tx = $st->get_result()->fetch_assoc();
        $st->close();

        if (empty($tx)) { $db->close(); jsonOut(404, ['ok' => false, 'message' => 'Transaction introuvable.']); }

        if ($tx['statut'] === 'succes') {
            $db->close();
            jsonOut(200, ['ok' => true, 'statut' => 'succes', 'message' => 'Paiement confirmé.']);
        }
        if ($tx['statut'] === 'echec') {
            $db->close();
            jsonOut(200, ['ok' => true, 'statut' => 'echec', 'message' => 'Transaction échouée.']);
        }

        $resp   = flexpaieGet($ref);
        $fpCode = (int)($resp['code'] ?? 1);
        $fpMsg  = (string)($resp['message'] ?? '');

        if ($fpCode === 0 || strtolower($fpMsg) === 'successful') {
            if ($tx['type'] === 'depot') {
                $montant = (float)$tx['montant'];
                $stcr = $db->prepare("UPDATE utilisateurs SET solde_depot = solde_depot + ? WHERE id = ?");
                $stcr->bind_param('di', $montant, $user_id); $stcr->execute(); $stcr->close();
                addNotif($db, $user_id, 'depot', "Dépôt {$montant} {$tx['devise']} crédité (réf: {$ref}).");
            }
            $txid = (int)$tx['id'];
            $stok = $db->prepare("UPDATE transactions_finance SET statut='succes', flexpaie_code=?, flexpaie_message=?, updated_at=NOW() WHERE id=?");
            $stok->bind_param('isi', $fpCode, $fpMsg, $txid); $stok->execute(); $stok->close();
            $db->close();
            jsonOut(200, ['ok' => true, 'statut' => 'succes', 'message' => 'Paiement confirmé !']);
        }

        $statut = 'pending';
        if (in_array(strtolower($fpMsg), ['failed', 'echec', 'error', 'cancelled', 'canceled', 'rejected'], true) || $fpCode >= 2) {
            $statut = 'echec';
            $srcCol = (string)($tx['source_solde'] ?? '');
            $allowedCols = ['solde_depot', 'solde_gain', 'portefeuille'];
            if ($tx['type'] === 'retrait' && in_array($srcCol, $allowedCols, true)) {
                $montant = (float)$tx['montant'];
                $stref = $db->prepare("UPDATE utilisateurs SET `{$srcCol}` = `{$srcCol}` + ? WHERE id = ?");
                $stref->bind_param('di', $montant, $user_id); $stref->execute(); $stref->close();
                addNotif($db, $user_id, 'retrait_echec', "Retrait {$montant} {$tx['devise']} échoué. Solde remboursé (réf: {$ref}).");
            }
        }

        $txid2 = (int)$tx['id'];
        $stup = $db->prepare("UPDATE transactions_finance SET statut=?, flexpaie_code=?, flexpaie_message=?, updated_at=NOW() WHERE id=?");
        $stup->bind_param('sisi', $statut, $fpCode, $fpMsg, $txid2); $stup->execute(); $stup->close();
        $db->close();
        jsonOut(200, ['ok' => true, 'statut' => $statut, 'message' => $statut === 'echec' ? 'Transaction échouée.' : 'En attente de confirmation...']);
    }

    jsonOut(400, ['ok' => false, 'message' => 'Action inconnue.']);
}

/* ═════════════════════════════ INIT PAGE HTML ══════════════════════════ */

$db   = dbOrFail();
$user = loadUser($db, $user_id);
$db->close();

if (empty($user)) {
    session_unset(); session_destroy();
    header('Location: connexion.php');
    exit;
}

$solde_depot  = number_format((float)$user['solde_depot'],  0, ',', ' ');
$solde_gain   = number_format((float)$user['solde_gain'],   0, ',', ' ');
$portefeuille = number_format((float)$user['portefeuille'], 0, ',', ' ');
$nom          = htmlspecialchars((string)($user['surnom_de_jeux'] ?? 'Utilisateur'), ENT_QUOTES, 'UTF-8');
$tel_def      = htmlspecialchars(normalizeTel((string)($user['telephone'] ?? '')), ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Finance – TETH PAY</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f1117;--card:#1a1d2e;--card2:#22263a;--accent:#7c3aed;--accent2:#6d28d9;
  --green:#10b981;--red:#ef4444;--yellow:#f59e0b;--text:#e5e7eb;--muted:#9ca3af;
  --border:#2d3148;--radius:12px;--shadow:0 4px 24px rgba(0,0,0,.4);
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
a{color:var(--accent);text-decoration:none}
button{cursor:pointer;border:none;outline:none}
input,select{outline:none}

/* NAV */
.nav{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;
     background:var(--card);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.nav-brand{font-size:1.2rem;font-weight:700;color:var(--accent)}
.nav-user{font-size:.9rem;color:var(--muted)}
.nav-back{background:var(--card2);color:var(--text);padding:6px 16px;border-radius:8px;
          font-size:.85rem;border:1px solid var(--border);transition:.2s}
.nav-back:hover{background:var(--accent);color:#fff}

/* LAYOUT */
.page{max-width:900px;margin:0 auto;padding:24px 16px}
.page-title{font-size:1.5rem;font-weight:700;margin-bottom:20px}

/* BALANCES */
.balances{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:28px}
.bal-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
          padding:18px 20px;display:flex;flex-direction:column;gap:6px}
.bal-label{font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.bal-value{font-size:1.4rem;font-weight:700}
.bal-devise{font-size:.8rem;color:var(--muted)}
.bal-depot .bal-value{color:var(--accent)}
.bal-gain  .bal-value{color:var(--green)}
.bal-port  .bal-value{color:var(--yellow)}

/* TABS */
.tabs{display:flex;gap:4px;background:var(--card);border-radius:10px;padding:4px;
      border:1px solid var(--border);width:fit-content;margin-bottom:24px}
.tab-btn{padding:8px 24px;border-radius:8px;font-size:.9rem;font-weight:600;
         background:transparent;color:var(--muted);transition:.2s}
.tab-btn.active{background:var(--accent);color:#fff}
.tab-btn:hover:not(.active){background:var(--card2);color:var(--text)}
.tab-panel{display:none}
.tab-panel.active{display:block}

/* CARD */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
      padding:24px;box-shadow:var(--shadow);margin-bottom:24px}
.card-title{font-size:1rem;font-weight:700;margin-bottom:20px;color:var(--text)}

/* FORM */
.form-group{margin-bottom:18px}
.form-label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:6px}
.form-input{width:100%;background:var(--card2);border:1px solid var(--border);
            border-radius:8px;padding:10px 14px;color:var(--text);font-size:.95rem;transition:.2s}
.form-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,58,237,.2)}
.form-select{width:100%;background:var(--card2);border:1px solid var(--border);
             border-radius:8px;padding:10px 14px;color:var(--text);font-size:.95rem;
             appearance:none;cursor:pointer}
.form-hint{font-size:.78rem;color:var(--muted);margin-top:4px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:560px){.form-row{grid-template-columns:1fr}}

/* BOUTONS */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
     padding:11px 28px;border-radius:10px;font-size:.95rem;font-weight:600;transition:.2s;width:100%}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover:not(:disabled){background:var(--accent2)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover:not(:disabled){background:#dc2626}

/* SPINNER */
.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.3);
         border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;display:none}
@keyframes spin{to{transform:rotate(360deg)}}

/* STATUS BADGE */
.status-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.78rem;font-weight:600}
.s-pending{background:rgba(245,158,11,.15);color:var(--yellow)}
.s-succes {background:rgba(16,185,129,.15);color:var(--green)}
.s-echec  {background:rgba(239,68,68,.15); color:var(--red)}

/* POLL BOX */
.poll-box{display:none;margin-top:20px;background:var(--card2);border:1px solid var(--border);
          border-radius:var(--radius);padding:20px;text-align:center}
.poll-box.show{display:block}
.poll-ref{font-size:.85rem;color:var(--muted);margin-bottom:10px;word-break:break-all}
.poll-status{font-size:1rem;font-weight:600;margin-bottom:8px}
.poll-msg{font-size:.85rem;color:var(--muted)}
.poll-icon{font-size:2rem;margin-bottom:8px}

/* HISTORY TABLE */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.88rem}
thead tr{background:var(--card2)}
th{padding:10px 12px;text-align:left;color:var(--muted);font-weight:600;white-space:nowrap}
td{padding:10px 12px;border-top:1px solid var(--border);white-space:nowrap}
tr:hover td{background:rgba(124,58,237,.05)}
.no-rows{text-align:center;color:var(--muted);padding:30px}
.pager{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}
.pager-btn{background:var(--card2);border:1px solid var(--border);color:var(--text);
           padding:6px 14px;border-radius:8px;font-size:.85rem;cursor:pointer;transition:.2s}
.pager-btn:hover:not(:disabled){background:var(--accent);color:#fff;border-color:var(--accent)}
.pager-btn:disabled{opacity:.4;cursor:not-allowed}

/* TOAST */
#toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{padding:12px 20px;border-radius:10px;font-size:.9rem;font-weight:500;
       box-shadow:var(--shadow);max-width:340px;animation:slideIn .3s ease}
.toast-success{background:#10b98120;border:1px solid var(--green);color:var(--green)}
.toast-error  {background:#ef444420;border:1px solid var(--red);color:var(--red)}
.toast-info   {background:#7c3aed20;border:1px solid var(--accent);color:var(--accent)}
@keyframes slideIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}
</style>
</head>
<body>

<nav class="nav">
  <span class="nav-brand">⚡ TETH PAY</span>
  <span class="nav-user">👤 <?= $nom ?></span>
  <button class="nav-back" onclick="location.href='espace_client.php'">← Retour</button>
</nav>

<div class="page">
  <div class="page-title">💰 Finance</div>

  <!-- BALANCES -->
  <div class="balances">
    <div class="bal-card bal-depot">
      <span class="bal-label">Solde Dépôt</span>
      <span class="bal-value" id="val-depot"><?= $solde_depot ?></span>
      <span class="bal-devise"><?= DEFAULT_DEVISE ?></span>
    </div>
    <div class="bal-card bal-gain">
      <span class="bal-label">Solde Gains</span>
      <span class="bal-value" id="val-gain"><?= $solde_gain ?></span>
      <span class="bal-devise"><?= DEFAULT_DEVISE ?></span>
    </div>
    <div class="bal-card bal-port">
      <span class="bal-label">Portefeuille</span>
      <span class="bal-value" id="val-port"><?= $portefeuille ?></span>
      <span class="bal-devise"><?= DEFAULT_DEVISE ?></span>
    </div>
  </div>

  <!-- TABS -->
  <div class="tabs">
    <button class="tab-btn active" data-tab="depot">📥 Dépôt</button>
    <button class="tab-btn"       data-tab="retrait">📤 Retrait</button>
    <button class="tab-btn"       data-tab="historique">📋 Historique</button>
  </div>

  <!-- ▸ DEPOT -->
  <div class="tab-panel active" id="tab-depot">
    <div class="card">
      <div class="card-title">📥 Effectuer un Dépôt (Mobile Money)</div>
      <form id="form-depot" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($CSRF, ENT_QUOTES) ?>">
        <input type="hidden" name="action" value="init_depot">
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Montant (<?= DEFAULT_DEVISE ?>)</label>
            <input class="form-input" type="number" name="montant" min="<?= MIN_DEPOT_FC ?>" max="<?= MAX_DEPOT_FC ?>" step="100" placeholder="ex: 5000" required>
            <div class="form-hint">Min <?= number_format(MIN_DEPOT_FC, 0, ',', ' ') ?> – Max <?= number_format(MAX_DEPOT_FC, 0, ',', ' ') ?></div>
          </div>
          <div class="form-group">
            <label class="form-label">Téléphone Mobile Money</label>
            <input class="form-input" type="tel" name="telephone" value="<?= $tel_def ?>" placeholder="ex: 0999000000" required>
            <div class="form-hint">Airtel ou Vodacom</div>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Mot de passe de confirmation</label>
          <input class="form-input" type="password" name="pwd" placeholder="Votre mot de passe" required autocomplete="current-password">
        </div>
        <button class="btn btn-primary" type="submit" id="btn-depot">
          <span class="spinner" id="sp-depot"></span>
          <span id="btn-depot-txt">💸 Initier le dépôt</span>
        </button>
      </form>
      <div class="poll-box" id="poll-depot">
        <div class="poll-icon" id="pi-depot">⏳</div>
        <div class="poll-status" id="ps-depot">En attente…</div>
        <div class="poll-ref"   id="pr-depot"></div>
        <div class="poll-msg"   id="pm-depot">Validez la demande sur votre téléphone.</div>
      </div>
    </div>
  </div>

  <!-- ▸ RETRAIT -->
  <div class="tab-panel" id="tab-retrait">
    <div class="card">
      <div class="card-title">📤 Effectuer un Retrait</div>
      <form id="form-retrait" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($CSRF, ENT_QUOTES) ?>">
        <input type="hidden" name="action" value="init_retrait">
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Montant (<?= DEFAULT_DEVISE ?>)</label>
            <input class="form-input" type="number" name="montant" min="<?= MIN_RETRAIT_FC ?>" max="<?= MAX_RETRAIT_FC ?>" step="100" placeholder="ex: 10000" required>
            <div class="form-hint">Min <?= number_format(MIN_RETRAIT_FC, 0, ',', ' ') ?> – Max <?= number_format(MAX_RETRAIT_FC, 0, ',', ' ') ?></div>
          </div>
          <div class="form-group">
            <label class="form-label">Téléphone Mobile Money</label>
            <input class="form-input" type="tel" name="telephone" value="<?= $tel_def ?>" placeholder="ex: 0999000000" required>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Source du solde</label>
          <select class="form-select" name="source">
            <option value="solde_depot">Solde Dépôt (<?= $solde_depot ?> <?= DEFAULT_DEVISE ?>)</option>
            <option value="solde_gain">Solde Gains (<?= $solde_gain ?> <?= DEFAULT_DEVISE ?>)</option>
            <option value="portefeuille">Portefeuille (<?= $portefeuille ?> <?= DEFAULT_DEVISE ?>)</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Mot de passe de confirmation</label>
          <input class="form-input" type="password" name="pwd" placeholder="Votre mot de passe" required autocomplete="current-password">
        </div>
        <button class="btn btn-danger" type="submit" id="btn-retrait">
          <span class="spinner" id="sp-retrait"></span>
          <span id="btn-retrait-txt">📤 Initier le retrait</span>
        </button>
      </form>
      <div class="poll-box" id="poll-retrait">
        <div class="poll-icon" id="pi-retrait">⏳</div>
        <div class="poll-status" id="ps-retrait">En attente…</div>
        <div class="poll-ref"   id="pr-retrait"></div>
        <div class="poll-msg"   id="pm-retrait">Traitement en cours…</div>
      </div>
    </div>
  </div>

  <!-- ▸ HISTORIQUE -->
  <div class="tab-panel" id="tab-historique">
    <div class="card">
      <div class="card-title">📋 Historique des transactions</div>
      <div class="tbl-wrap">
        <table id="tbl-hist">
          <thead>
            <tr>
              <th>#</th><th>Type</th><th>Montant</th><th>Téléphone</th>
              <th>Référence</th><th>Statut</th><th>Date</th>
            </tr>
          </thead>
          <tbody id="hist-body">
            <tr><td colspan="7" class="no-rows">Chargement…</td></tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button class="pager-btn" id="pg-prev" disabled>‹ Préc.</button>
        <span id="pg-info" style="font-size:.85rem;color:var(--muted);line-height:30px">Page 1</span>
        <button class="pager-btn" id="pg-next" disabled>Suiv. ›</button>
      </div>
    </div>
  </div>
</div><!-- /page -->

<div id="toast-container"></div>

<script>
(function(){
'use strict';

const CSRF = <?= json_encode($CSRF) ?>;
const DEVISE = '<?= DEFAULT_DEVISE ?>';
let histPage = 1, histTotal = 0, histLimit = 15;

/* ── TABS ── */
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn,.tab-panel').forEach(el => el.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'historique') loadHistory(1);
  });
});

/* ── TOAST ── */
function toast(msg, type='info'){
  const c = document.getElementById('toast-container');
  const d = document.createElement('div');
  d.className = 'toast toast-' + type;
  d.textContent = msg;
  c.appendChild(d);
  setTimeout(()=>d.remove(), 4200);
}

/* ── BALANCES REFRESH ── */
function refreshBalances(){
  fetch('finance.php?action=get_solde', {headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(r=>r.json()).then(d=>{
      if(!d.ok) return;
      document.getElementById('val-depot').textContent = fmt(d.solde_depot);
      document.getElementById('val-gain').textContent  = fmt(d.solde_gain);
      document.getElementById('val-port').textContent  = fmt(d.portefeuille);
    }).catch(()=>{});
}
function fmt(n){ return Number(n).toLocaleString('fr-FR'); }

/* ── AJAX FORM ── */
function submitForm(formId, btnId, spId, txtId, pollId, piId, psId, prId, pmId){
  const form = document.getElementById(formId);
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = document.getElementById(btnId);
    const sp  = document.getElementById(spId);
    const txt = document.getElementById(txtId);
    btn.disabled = true; sp.style.display = 'inline-block'; txt.textContent = 'Envoi…';

    const fd = new FormData(form);
    try {
      const r = await fetch('finance.php', {
        method:'POST', body: fd, headers:{'X-Requested-With':'XMLHttpRequest'}
      });
      const d = await r.json();
      if(d.reload){ toast(d.message||'Session expirée.','error'); setTimeout(()=>location.reload(),1500); return; }
      if(d.redirect){ location.href = d.redirect; return; }
      if(!d.ok){ toast(d.message||'Erreur.','error'); return; }

      toast(d.message||'Demande envoyée.','success');
      form.querySelector('[name="pwd"]').value = '';
      refreshBalances();

      const pb = document.getElementById(pollId);
      pb.classList.add('show');
      document.getElementById(prId).textContent = 'Réf: ' + d.ref;
      pollStatus(d.ref, d.tx_id, piId, psId, pmId, () => {
        refreshBalances();
        loadHistory(1);
        pb.classList.remove('show');
      });
    } catch(err){
      toast('Erreur réseau. Réessayez.','error');
    } finally {
      btn.disabled = false; sp.style.display = 'none';
      txt.textContent = formId === 'form-depot' ? '💸 Initier le dépôt' : '📤 Initier le retrait';
    }
  });
}

/* ── POLL STATUS ── */
function pollStatus(ref, txId, piId, psId, pmId, onDone){
  let tries = 0, maxTries = 24;
  const pi = document.getElementById(piId);
  const ps = document.getElementById(psId);
  const pm = document.getElementById(pmId);

  function check(){
    fetch('finance.php?action=check_status&ref='+encodeURIComponent(ref)+'&tx_id='+txId,
          {headers:{'X-Requested-With':'XMLHttpRequest'}})
      .then(r=>r.json()).then(d=>{
        if(!d.ok){ ps.textContent='Erreur vérification.'; pi.textContent='❌'; return; }
        if(d.statut==='succes'){
          pi.textContent='✅'; ps.textContent='Confirmé !';
          pm.textContent='Transaction réussie.';
          toast('Transaction confirmée !','success');
          setTimeout(onDone, 1500);
          return;
        }
        if(d.statut==='echec'){
          pi.textContent='❌'; ps.textContent='Échec.';
          pm.textContent = d.message || 'Transaction échouée.';
          toast('Transaction échouée.','error');
          setTimeout(onDone, 2500);
          return;
        }
        tries++;
        if(tries >= maxTries){
          pi.textContent='⚠️'; ps.textContent='Timeout.';
          pm.textContent='Vérifiez votre téléphone ou contactez le support.';
          toast('Délai dépassé. Vérifiez votre téléphone.','info');
          return;
        }
        ps.textContent = 'En attente… (' + tries + '/' + maxTries + ')';
        setTimeout(check, 10000);
      }).catch(()=>{ tries++; if(tries<maxTries) setTimeout(check,12000); });
  }
  setTimeout(check, 15000);
}

/* ── HISTORIQUE ── */
function loadHistory(page){
  histPage = page;
  const tbody = document.getElementById('hist-body');
  tbody.innerHTML = '<tr><td colspan="7" class="no-rows">Chargement…</td></tr>';
  fetch('finance.php?action=get_history&page='+page+'&limit='+histLimit,
        {headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(r=>r.json()).then(d=>{
      if(!d.ok){ tbody.innerHTML='<tr><td colspan="7" class="no-rows">Erreur chargement.</td></tr>'; return; }
      histTotal = d.total;
      if(!d.rows || d.rows.length===0){
        tbody.innerHTML='<tr><td colspan="7" class="no-rows">Aucune transaction.</td></tr>';
      } else {
        tbody.innerHTML = d.rows.map((r,i)=>`
          <tr>
            <td>${(page-1)*histLimit+i+1}</td>
            <td>${r.type==='depot'?'📥 Dépôt':'📤 Retrait'}</td>
            <td><strong>${fmt(r.montant)}</strong> <small>${r.devise||DEVISE}</small></td>
            <td>${r.telephone||'–'}</td>
            <td><code style="font-size:.8rem">${r.reference_externe||'–'}</code></td>
            <td><span class="status-badge s-${r.statut}">${labelStatut(r.statut)}</span></td>
            <td>${r.created_fmt||'–'}</td>
          </tr>`).join('');
      }
      document.getElementById('pg-info').textContent =
        'Page '+ page +' / '+ Math.max(1, Math.ceil(histTotal/histLimit));
      document.getElementById('pg-prev').disabled = (page <= 1);
      document.getElementById('pg-next').disabled = (page * histLimit >= histTotal);
    }).catch(()=>{ tbody.innerHTML='<tr><td colspan="7" class="no-rows">Erreur réseau.</td></tr>'; });
}

function labelStatut(s){
  return s==='succes'?'Succès': s==='echec'?'Échec': s==='pending'?'En cours':'–';
}

document.getElementById('pg-prev').addEventListener('click', ()=>loadHistory(histPage-1));
document.getElementById('pg-next').addEventListener('click', ()=>loadHistory(histPage+1));

/* ── INIT FORMS ── */
submitForm('form-depot',   'btn-depot',   'sp-depot',   'btn-depot-txt',   'poll-depot',   'pi-depot',   'ps-depot',   'pr-depot',   'pm-depot');
submitForm('form-retrait', 'btn-retrait', 'sp-retrait', 'btn-retrait-txt', 'poll-retrait', 'pi-retrait', 'ps-retrait', 'pr-retrait', 'pm-retrait');

/* ── AUTO-REFRESH BALANCES every 60s ── */
setInterval(refreshBalances, 60000);

})();
</script>
</body>
</html>
