<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/supabase.php';
enforce_session_timeout();

const ADMIN_PRIME_ID = '00000000-0000-0000-0000-000000000001';

$flash = $_SESSION['flash'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash'], $_SESSION['flash_error']);

function current_admin_id(): ?string
{
    return $_SESSION['admin']['id'] ?? null;
}

function current_admin_role(): ?string
{
    return $_SESSION['admin']['role'] ?? null;
}

function is_adminprime(): bool
{
    return current_admin_id() === ADMIN_PRIME_ID && current_admin_role() === 'adminprime';
}

function require_admin_login(): void
{
    if (!isset($_SESSION['admin'])) {
        $_SESSION['flash_error'] = 'Admin sign-in is required.';
        header('Location: admin.php');
        exit;
    }
}

function block_adminprime_mutation(string $targetAdminId, string $operation): void
{
    if ($targetAdminId === ADMIN_PRIME_ID && in_array(strtoupper($operation), ['DELETE', 'UPDATE'], true)) {
        audit_log(current_admin_id(), 'blocked_adminprime_' . strtolower($operation));
        http_response_code(403);
        exit('Security policy blocked this request: ADMIN_PRIME_ID cannot be deleted, updated, removed, or downgraded.');
    }
}

function redirect_admin(): void
{
    header('Location: admin.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'login') {
        $email = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $lookup = supabase_request('GET', 'admins', null, [
            'email' => 'eq.' . $email,
            'select' => '*',
            'limit' => '1',
        ]);
        $admin = $lookup['data'][0] ?? null;

        if ($admin && password_verify($password, (string) ($admin['password_hash'] ?? ''))) {
            $_SESSION['admin'] = [
                'id' => $admin['id'],
                'name' => $admin['name'],
                'email' => $admin['email'],
                'role' => $admin['role'],
            ];
            audit_log($admin['id'], 'admin_login');
            $_SESSION['flash'] = 'Welcome back, ' . $admin['name'] . '.';
        } else {
            $_SESSION['flash_error'] = 'Invalid admin credentials.';
        }
        redirect_admin();
    }

    if ($action === 'logout') {
        audit_log(current_admin_id(), 'admin_logout');
        session_unset();
        session_destroy();
        header('Location: admin.php');
        exit;
    }

    require_admin_login();

    if ($action === 'create_content') {
        $title = trim((string) ($_POST['title'] ?? ''));
        $category = trim((string) ($_POST['category'] ?? ''));
        $body = trim((string) ($_POST['body'] ?? ''));
        if ($title === '' || $category === '' || $body === '') {
            $_SESSION['flash_error'] = 'Course content needs a title, category, and body.';
        } else {
            supabase_request('POST', 'course_content', [
                'title' => $title,
                'category' => $category,
                'body' => $body,
                'created_by' => current_admin_id(),
                'created_at' => gmdate('c'),
            ]);
            audit_log(current_admin_id(), 'content_created:' . $title);
            $_SESSION['flash'] = 'Course content saved.';
        }
        redirect_admin();
    }

    if ($action === 'generate_key') {
        if (!is_adminprime()) {
            $_SESSION['flash_error'] = 'Only adminprime can generate secret keys.';
            audit_log(current_admin_id(), 'blocked_key_generation');
            redirect_admin();
        }

        $assignedName = trim((string) ($_POST['assigned_name'] ?? ''));
        $assignedWhatsapp = trim((string) ($_POST['assigned_whatsapp'] ?? ''));
        $assignedEmail = trim((string) ($_POST['assigned_email'] ?? ''));
        if ($assignedName === '' || $assignedWhatsapp === '' || !filter_var($assignedEmail, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['flash_error'] = 'Assign the key to a valid name, WhatsApp number, and email.';
            redirect_admin();
        }

        do {
            $key = generate_secret_key();
            $existing = supabase_request('GET', 'secret_keys', null, [
                'key' => 'eq.' . $key,
                'select' => 'id',
                'limit' => '1',
            ]);
        } while (($existing['data'] ?? []) !== []);

        supabase_request('POST', 'secret_keys', [
            'key' => $key,
            'assigned_name' => $assignedName,
            'assigned_whatsapp' => $assignedWhatsapp,
            'assigned_email' => $assignedEmail,
            'used' => false,
            'created_by' => current_admin_id(),
            'created_at' => gmdate('c'),
        ]);
        audit_log(current_admin_id(), 'secret_key_generated:' . $assignedEmail);
        $_SESSION['flash'] = 'Secret key generated: ' . $key;
        redirect_admin();
    }

    if ($action === 'onboard_premium_user') {
        $name = trim((string) ($_POST['premium_name'] ?? ''));
        $whatsapp = trim((string) ($_POST['premium_whatsapp'] ?? ''));
        $email = trim((string) ($_POST['premium_email'] ?? ''));
        $secretKey = trim((string) ($_POST['premium_key'] ?? ''));

        if ($name === '' || $whatsapp === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^starlabs-[A-Za-z0-9]+$/', $secretKey)) {
            $_SESSION['flash_error'] = 'Premium onboarding needs a name, WhatsApp number, valid email, and starlabs key.';
            redirect_admin();
        }

        $keyLookup = supabase_request('GET', 'secret_keys', null, [
            'key' => 'eq.' . $secretKey,
            'used' => 'eq.false',
            'select' => '*',
            'limit' => '1',
        ]);
        $keyRecord = $keyLookup['data'][0] ?? null;

        if (!$keyRecord) {
            $_SESSION['flash_error'] = 'This key is invalid or already used.';
            redirect_admin();
        }

        if (
            strcasecmp((string) ($keyRecord['assigned_email'] ?? ''), $email) !== 0 ||
            strcasecmp((string) ($keyRecord['assigned_name'] ?? ''), $name) !== 0 ||
            (string) ($keyRecord['assigned_whatsapp'] ?? '') !== $whatsapp
        ) {
            $_SESSION['flash_error'] = 'The key assignment does not match the submitted user details.';
            redirect_admin();
        }

        supabase_request('PATCH', 'secret_keys', [
            'used' => true,
            'used_at' => gmdate('c'),
        ], [
            'id' => 'eq.' . $keyRecord['id'],
        ]);

        supabase_request('POST', 'premium_users', [
            'name' => $name,
            'whatsapp' => $whatsapp,
            'email' => $email,
            'secret_key_id' => $keyRecord['id'],
            'created_at' => gmdate('c'),
        ]);
        audit_log(current_admin_id(), 'premium_user_onboarded:' . $email);
        $_SESSION['flash'] = 'Premium user onboarded and key marked as used.';
        redirect_admin();
    }

    if ($action === 'create_admin') {
        if (!is_adminprime()) {
            $_SESSION['flash_error'] = 'Only adminprime can create or manage admins.';
            audit_log(current_admin_id(), 'blocked_admin_creation');
            redirect_admin();
        }
        $name = trim((string) ($_POST['name'] ?? ''));
        $email = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $role = (string) ($_POST['role'] ?? 'subadmin');
        if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8 || !in_array($role, ['adminprime', 'subadmin'], true)) {
            $_SESSION['flash_error'] = 'Admin needs a name, valid email, 8-character password, and valid role.';
            redirect_admin();
        }
        supabase_request('POST', 'admins', [
            'name' => $name,
            'email' => $email,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'role' => $role,
            'created_by' => current_admin_id(),
            'created_at' => gmdate('c'),
        ]);
        audit_log(current_admin_id(), 'admin_created:' . $email);
        $_SESSION['flash'] = 'Admin account created.';
        redirect_admin();
    }

    if ($action === 'update_admin_role') {
        if (!is_adminprime()) {
            $_SESSION['flash_error'] = 'Only adminprime can update admin roles.';
            audit_log(current_admin_id(), 'blocked_admin_role_update');
            redirect_admin();
        }
        $targetId = (string) ($_POST['admin_id'] ?? '');
        block_adminprime_mutation($targetId, 'UPDATE');
        $role = (string) ($_POST['role'] ?? 'subadmin');
        if (!in_array($role, ['adminprime', 'subadmin'], true)) {
            $_SESSION['flash_error'] = 'Invalid role selected.';
            redirect_admin();
        }
        supabase_request('PATCH', 'admins', ['role' => $role], ['id' => 'eq.' . $targetId]);
        audit_log(current_admin_id(), 'admin_role_updated:' . $targetId);
        $_SESSION['flash'] = 'Admin role updated.';
        redirect_admin();
    }

    if ($action === 'delete_admin') {
        if (!is_adminprime()) {
            $_SESSION['flash_error'] = 'Only adminprime can delete admins.';
            audit_log(current_admin_id(), 'blocked_admin_delete');
            redirect_admin();
        }
        $targetId = (string) ($_POST['admin_id'] ?? '');
        block_adminprime_mutation($targetId, 'DELETE');
        supabase_request('DELETE', 'admins', null, ['id' => 'eq.' . $targetId]);
        audit_log(current_admin_id(), 'admin_deleted:' . $targetId);
        $_SESSION['flash'] = 'Admin deleted.';
        redirect_admin();
    }
}

$isLoggedIn = isset($_SESSION['admin']);
$stats = [
    'content' => '0',
    'premium' => '0',
    'keys' => '0',
];
$contentRows = [];
$keyRows = [];
$adminRows = [];
$auditRows = [];

if ($isLoggedIn) {
    $contentRows = supabase_request('GET', 'course_content', null, ['select' => '*', 'order' => 'created_at.desc', 'limit' => '8'])['data'] ?? [];
    $keyRows = supabase_request('GET', 'secret_keys', null, ['select' => '*', 'order' => 'created_at.desc', 'limit' => '8'])['data'] ?? [];
    $adminRows = is_adminprime() ? (supabase_request('GET', 'admins', null, ['select' => 'id,name,email,role,created_at', 'order' => 'created_at.desc'])['data'] ?? []) : [];
    $auditRows = supabase_request('GET', 'audit_logs', null, ['select' => '*', 'order' => 'timestamp.desc', 'limit' => '10'])['data'] ?? [];
    $stats['content'] = (string) count($contentRows);
    $stats['keys'] = (string) count($keyRows);
    $stats['premium'] = (string) count(supabase_request('GET', 'premium_users', null, ['select' => 'id', 'limit' => '100'])['data'] ?? []);
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Dashboard | YouTube Automation Courses</title>
  <link rel="stylesheet" href="assets/styles.css">
</head>
<body>
  <header class="site-header">
    <nav class="nav" aria-label="Primary navigation">
      <a class="brand" href="index.html"><span class="brand-mark">SL</span><span>YouTube Automation Courses</span></a>
      <div class="nav-links">
        <a href="index.html">Home</a>
        <a href="guides.html">Guides</a>
        <a href="premium-guide.php">Premium</a>
        <a aria-current="page" href="admin.php">Admin</a>
      </div>
    </nav>
  </header>

  <?php if (!$isLoggedIn): ?>
    <main class="container section">
      <div class="two-col">
        <div>
          <span class="eyebrow">Admin dashboard</span>
          <h1>Manage courses, keys, premium users, and audit trails.</h1>
          <p class="lead">Sessions expire after 7 minutes. Adminprime is the only role allowed to generate keys and manage other administrators.</p>
        </div>
        <div class="card">
          <h2>Sign In</h2>
          <?php if ($error): ?><p class="notice error"><?= h($error) ?></p><?php endif; ?>
          <form class="form-grid" method="post">
            <input type="hidden" name="action" value="login">
            <label>Email <input name="email" type="email" required autocomplete="email"></label>
            <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
            <button class="btn primary" type="submit">Open Dashboard</button>
          </form>
        </div>
      </div>
    </main>
  <?php else: ?>
    <main class="admin-shell">
      <aside class="admin-sidebar">
        <nav class="admin-nav" aria-label="Admin sections">
          <a href="#overview">Overview</a>
          <a href="#content">Content</a>
          <a href="#keys">Secret Keys</a>
          <a href="#admins">Admins</a>
          <a href="#audit">Audit Logs</a>
        </nav>
        <form method="post" style="margin-top: 18px;">
          <input type="hidden" name="action" value="logout">
          <button class="btn" type="submit">Sign Out</button>
        </form>
      </aside>
      <section class="admin-main">
        <div id="overview" class="section-head">
          <div>
            <span class="eyebrow"><?= h($_SESSION['admin']['role']) ?></span>
            <h1>Educational Dashboard</h1>
            <p class="section-intro">Signed in as <?= h($_SESSION['admin']['name']) ?>. This session will expire after 7 minutes of inactivity.</p>
          </div>
        </div>

        <?php if ($flash): ?><p class="notice"><?= h($flash) ?></p><?php endif; ?>
        <?php if ($error): ?><p class="notice error"><?= h($error) ?></p><?php endif; ?>

        <div class="metric-grid">
          <div class="metric"><span>Recent Content</span><strong><?= h($stats['content']) ?></strong></div>
          <div class="metric"><span>Premium Users</span><strong><?= h($stats['premium']) ?></strong></div>
          <div class="metric"><span>Recent Keys</span><strong><?= h($stats['keys']) ?></strong></div>
        </div>

        <section id="content" class="section">
          <div class="section-head">
            <div>
              <h2>Course Content</h2>
              <p class="section-intro">Sub-admins can create and update education content for the public and premium guides.</p>
            </div>
          </div>
          <form class="card form-grid" method="post">
            <input type="hidden" name="action" value="create_content">
            <label>Title <input name="title" required placeholder="Retention analytics checklist"></label>
            <label>Category <input name="category" required placeholder="Premium Guide"></label>
            <label>Body <textarea name="body" required placeholder="Write practical course content for creators."></textarea></label>
            <button class="btn primary" type="submit">Save Content</button>
          </form>
        </section>

        <section id="keys" class="section">
          <div class="section-head">
            <div>
              <h2>Secret Keys</h2>
              <p class="section-intro">Keys use the required starlabs format, are single-use, and must be assigned after payment verification.</p>
            </div>
          </div>
          <?php if (is_adminprime()): ?>
            <form class="card form-grid" method="post">
              <input type="hidden" name="action" value="generate_key">
              <label>User Name <input name="assigned_name" required></label>
              <label>WhatsApp Number <input name="assigned_whatsapp" required inputmode="tel"></label>
              <label>User Email <input name="assigned_email" type="email" required></label>
              <button class="btn gold" type="submit">Generate Assigned Key</button>
            </form>
          <?php else: ?>
            <p class="notice">Sub-admins can onboard premium users with provided keys, but only adminprime can generate new keys.</p>
          <?php endif; ?>
          <div class="table-wrap" style="margin-top: 18px;">
            <table>
              <thead><tr><th>Key</th><th>Assigned To</th><th>Used</th><th>Created</th></tr></thead>
              <tbody>
                <?php foreach ($keyRows as $row): ?>
                  <tr>
                    <td><?= h($row['key'] ?? '') ?></td>
                    <td><?= h(($row['assigned_name'] ?? '') . ' / ' . ($row['assigned_email'] ?? '')) ?></td>
                    <td><span class="badge"><?= !empty($row['used']) ? 'Used' : 'Available' ?></span></td>
                    <td><?= h($row['created_at'] ?? '') ?></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </section>

        <section id="premium-users" class="section">
          <div class="section-head">
            <div>
              <h2>Premium Onboarding</h2>
              <p class="section-intro">Admins can onboard paid students with a provided key after confirming the payment details.</p>
            </div>
          </div>
          <form class="card form-grid" method="post">
            <input type="hidden" name="action" value="onboard_premium_user">
            <label>Name <input name="premium_name" required></label>
            <label>WhatsApp Number <input name="premium_whatsapp" required inputmode="tel"></label>
            <label>Email <input name="premium_email" type="email" required></label>
            <label>Provided Secret Key <input name="premium_key" required placeholder="starlabs-"></label>
            <button class="btn primary" type="submit">Onboard Premium User</button>
          </form>
        </section>

        <section id="admins" class="section">
          <div class="section-head">
            <div>
              <h2>Admin Management</h2>
              <p class="section-intro">The ADMIN_PRIME_ID constant is protected from DELETE and UPDATE operations in this file.</p>
            </div>
          </div>
          <?php if (is_adminprime()): ?>
            <form class="card form-grid" method="post">
              <input type="hidden" name="action" value="create_admin">
              <label>Name <input name="name" required></label>
              <label>Email <input name="email" type="email" required></label>
              <label>Password <input name="password" type="password" minlength="8" required></label>
              <label>Role
                <select name="role">
                  <option value="subadmin">Sub-admin</option>
                  <option value="adminprime">Adminprime</option>
                </select>
              </label>
              <button class="btn primary" type="submit">Create Admin</button>
            </form>
            <div class="table-wrap" style="margin-top: 18px;">
              <table>
                <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead>
                <tbody>
                  <?php foreach ($adminRows as $admin): ?>
                    <tr>
                      <td><?= h($admin['name'] ?? '') ?></td>
                      <td><?= h($admin['email'] ?? '') ?></td>
                      <td><span class="badge"><?= h($admin['role'] ?? '') ?></span></td>
                      <td>
                        <?php if (($admin['id'] ?? '') !== ADMIN_PRIME_ID): ?>
                          <form method="post" style="display:inline-flex; gap: 8px; align-items:center;">
                            <input type="hidden" name="action" value="update_admin_role">
                            <input type="hidden" name="admin_id" value="<?= h($admin['id'] ?? '') ?>">
                            <select name="role" aria-label="Role">
                              <option value="subadmin">Sub-admin</option>
                              <option value="adminprime">Adminprime</option>
                            </select>
                            <button class="btn" type="submit">Update</button>
                          </form>
                          <form method="post" style="display:inline-flex; margin-left: 8px;">
                            <input type="hidden" name="action" value="delete_admin">
                            <input type="hidden" name="admin_id" value="<?= h($admin['id'] ?? '') ?>">
                            <button class="btn danger" type="submit">Delete</button>
                          </form>
                        <?php else: ?>
                          <span class="badge">Protected primary admin</span>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php else: ?>
            <p class="notice">Admin management is restricted to adminprime.</p>
          <?php endif; ?>
        </section>

        <section id="audit" class="section">
          <div class="section-head">
            <div>
              <h2>Audit Logs</h2>
              <p class="section-intro">Every content change, user creation, key generation, and admin action writes to Supabase audit_logs.</p>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Admin ID</th><th>Action</th><th>Timestamp</th></tr></thead>
              <tbody>
                <?php foreach ($auditRows as $row): ?>
                  <tr>
                    <td><?= h($row['admin_id'] ?? 'system') ?></td>
                    <td><?= h($row['action_type'] ?? '') ?></td>
                    <td><?= h($row['timestamp'] ?? '') ?></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </section>
      </section>
    </main>
  <?php endif; ?>

  <footer class="site-footer">
    <div class="container footer-grid">
      <div>
        <strong>Website designed by Star Labs. All rights reserved.</strong>
        <p class="footer-copy">Donations support independent content creators by funding templates, research tools, and practical training resources.</p>
      </div>
      <div class="footer-links">
        <a class="btn" href="https://whatsapp.com/channel/0029Vb7Vhu8HwXbKCzWIWz04">WhatsApp Channel</a>
        <a class="btn primary" href="#donate">Donate</a>
      </div>
    </div>
  </footer>
</body>
</html>
