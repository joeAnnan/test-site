<?php
declare(strict_types=1);

const SUPABASE_URL = 'https://YOUR_PROJECT_REF.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = 'YOUR_SUPABASE_SERVICE_ROLE_KEY';

function supabase_request(string $method, string $path, ?array $payload = null, array $query = []): array
{
    $url = rtrim(SUPABASE_URL, '/') . '/rest/v1/' . ltrim($path, '/');
    if ($query !== []) {
        $url .= '?' . http_build_query($query);
    }

    $headers = [
        'apikey: ' . SUPABASE_SERVICE_ROLE_KEY,
        'Authorization: Bearer ' . SUPABASE_SERVICE_ROLE_KEY,
        'Content-Type: application/json',
        'Accept: application/json',
        'Prefer: return=representation',
    ];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
    ]);

    if ($payload !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_THROW_ON_ERROR));
    }

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'status' => 0, 'data' => null, 'error' => $error ?: 'Supabase request failed.'];
    }

    $decoded = $body !== '' ? json_decode($body, true) : null;
    if ($status < 200 || $status >= 300) {
        return ['ok' => false, 'status' => $status, 'data' => $decoded, 'error' => $body];
    }

    return ['ok' => true, 'status' => $status, 'data' => $decoded, 'error' => null];
}

function audit_log(?string $adminId, string $actionType): void
{
    supabase_request('POST', 'audit_logs', [
        'admin_id' => $adminId,
        'action_type' => $actionType,
        'timestamp' => gmdate('c'),
    ]);
}

function enforce_session_timeout(): void
{
    $now = time();
    if (isset($_SESSION['last_activity']) && ($now - (int) $_SESSION['last_activity']) > 420) {
        session_unset();
        session_destroy();
        session_start();
        $_SESSION['flash_error'] = 'Your session expired after 7 minutes. Please sign in again.';
    }
    $_SESSION['last_activity'] = $now;
}

function generate_secret_key(): string
{
    $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $token = '';
    for ($i = 0; $i < 24; $i++) {
        $token .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return 'starlabs-' . $token;
}

function require_post(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('Method not allowed.');
    }
}

function h(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}
