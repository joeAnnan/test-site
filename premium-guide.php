<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/supabase.php';
enforce_session_timeout();

$premiumMessage = '';
$premiumError = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'premium_login') {
    $name = trim((string) ($_POST['name'] ?? ''));
    $whatsapp = trim((string) ($_POST['whatsapp'] ?? ''));
    $email = trim((string) ($_POST['email'] ?? ''));
    $secretKey = trim((string) ($_POST['secret_key'] ?? ''));

    if ($name === '' || $whatsapp === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^starlabs-[A-Za-z0-9]+$/', $secretKey)) {
        $premiumError = 'Enter your name, WhatsApp number, valid email, and assigned Star Labs key.';
    } else {
        $keyLookup = supabase_request('GET', 'secret_keys', null, [
            'key' => 'eq.' . $secretKey,
            'used' => 'eq.false',
            'select' => '*',
            'limit' => '1',
        ]);

        $keyRecord = $keyLookup['data'][0] ?? null;
        if (!$keyLookup['ok'] || !$keyRecord) {
            $premiumError = 'This secret key is invalid, already used, or not assigned.';
        } elseif (
            strcasecmp((string) ($keyRecord['assigned_email'] ?? ''), $email) !== 0 ||
            strcasecmp((string) ($keyRecord['assigned_name'] ?? ''), $name) !== 0 ||
            (string) ($keyRecord['assigned_whatsapp'] ?? '') !== $whatsapp
        ) {
            $premiumError = 'This key is not assigned to the submitted payment details.';
        } else {
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

            $_SESSION['premium_user'] = [
                'name' => $name,
                'email' => $email,
            ];
            audit_log(null, 'premium_user_access_granted:' . $email);
            $premiumMessage = 'Premium access unlocked. Welcome to the advanced automation guide.';
        }
    }
}

$hasPremium = isset($_SESSION['premium_user']);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Premium Guide | YouTube Automation Courses</title>
  <link rel="stylesheet" href="assets/styles.css">
</head>
<body>
  <header class="site-header">
    <nav class="nav" aria-label="Primary navigation">
      <a class="brand" href="index.html"><span class="brand-mark">SL</span><span>YouTube Automation Courses</span></a>
      <div class="nav-links">
        <a href="index.html">Home</a>
        <a href="guides.html">Guides</a>
        <a aria-current="page" href="premium-guide.php">Premium</a>
        <a href="admin.php">Admin</a>
      </div>
    </nav>
  </header>

  <main>
    <section class="course-hero">
      <div>
        <div class="course-tags">
          <span class="course-tag">premium</span>
          <span class="course-tag">scaling</span>
          <span class="course-tag">creator operations</span>
        </div>
        <h1>Premium YouTube Automation Systems</h1>
        <p class="lead">Advanced training for hiring, production quality control, retention reviews, monetization planning, and channel scaling.</p>
        <div class="actions">
          <?php if ($hasPremium): ?>
            <a class="btn primary" href="#premium-curriculum">Start Premium Course</a>
          <?php else: ?>
            <button class="btn gold" data-modal-open="#premium-modal" aria-haspopup="dialog"><span class="crown-icon" aria-hidden="true">&#9819;</span> Unlock Premium</button>
          <?php endif; ?>
          <a class="btn" href="guides.html">Beginners Guide</a>
        </div>
      </div>
      <div class="course-media">
        Premium Growth Lab
        <span class="play-button" aria-hidden="true">&#9658;</span>
      </div>
    </section>

    <section class="container section">
      <?php if ($premiumError): ?><p class="notice error"><?= h($premiumError) ?></p><?php endif; ?>
      <?php if ($premiumMessage): ?><p class="notice"><?= h($premiumMessage) ?></p><?php endif; ?>

      <div class="course-note">
        <strong>Premium access:</strong> after payment verification, Star Labs assigns one single-use key to the student's name, WhatsApp number, and email. The key unlocks this guide and is then marked as used.
      </div>

      <?php if (!$hasPremium): ?>
        <div class="lesson-feature">
          <div class="lesson-image">Locked Premium Curriculum</div>
          <div>
            <span class="eyebrow">Golden Button Access</span>
            <h2>Unlock the advanced course viewer</h2>
            <p class="lead">Use the crown button to open the payment/login modal. Once verified, the premium lessons load on this page with automated lesson switching.</p>
            <div class="actions">
              <button class="btn gold" data-modal-open="#premium-modal"><span class="crown-icon" aria-hidden="true">&#9819;</span> Unlock Premium</button>
            </div>
          </div>
        </div>
      <?php else: ?>
        <div class="award-row">
          <span>Awarded upon completion:</span>
          <span class="xp">500xp</span>
          <span>+ Scaling operations playbook</span>
        </div>
      <?php endif; ?>
    </section>

    <?php if ($hasPremium): ?>
      <section class="container section" id="premium-curriculum" data-course-viewer>
        <div class="section-head">
          <div>
            <h2>Premium Curriculum</h2>
            <p class="section-intro">Browse advanced lessons on this same page. Add more modules by adding more curriculum buttons with lesson data.</p>
          </div>
        </div>

        <div class="course-viewer">
          <aside class="curriculum-list" aria-label="Premium lessons">
            <button class="lesson-button active" type="button" data-lesson data-title="Hiring and Team Roles" data-kicker="Premium Chapter 1" data-media="Team SOP Board" data-outcome="Outcome: create role cards for researcher, writer, voice artist, editor, thumbnail designer, and channel manager." data-body="Treat the channel like a small editorial team. Define responsibilities, turnaround times, quality gates, file naming, revision rules, and who approves the final upload. Clear roles prevent missed details as volume increases.">
              <strong>1. Hiring System</strong>
              <span>Build a dependable production team.</span>
            </button>
            <button class="lesson-button" type="button" data-lesson data-title="Quality Control Checklist" data-kicker="Premium Chapter 2" data-media="QC Pipeline" data-outcome="Outcome: review every asset before upload using a consistent quality checklist." data-body="Check factual accuracy, audio clarity, pacing, visual variety, copyright safety, thumbnail readability, title promise, and description links. Quality control protects retention and keeps the channel brand trustworthy.">
              <strong>2. Quality Control</strong>
              <span>Protect the viewer experience.</span>
            </button>
            <button class="lesson-button" type="button" data-lesson data-title="Retention Analytics Loop" data-kicker="Premium Chapter 3" data-media="Retention Graph" data-outcome="Outcome: turn dips and spikes into specific editing and scripting decisions." data-body="Review the first 30 seconds, major drop-off points, replayed moments, chapter pacing, and comments. Translate the data into next-video decisions: shorter setup, stronger visual proof, faster transitions, or clearer examples.">
              <strong>3. Retention Loop</strong>
              <span>Use analytics to improve watch time.</span>
            </button>
            <button class="lesson-button" type="button" data-lesson data-title="Content Budgeting and Profit" data-kicker="Premium Chapter 4" data-media="Budget Planner" data-outcome="Outcome: know the cost per video, break-even point, and monetization stack before scaling." data-body="Track research, script, voiceover, editing, thumbnail, tools, and management costs. Pair the cost model with AdSense projections, affiliate revenue, sponsors, products, and email capture so growth is financially controlled.">
              <strong>4. Budgeting</strong>
              <span>Scale without guessing costs.</span>
            </button>
            <button class="lesson-button" type="button" data-lesson data-title="Sponsorship and Offer Map" data-kicker="Premium Chapter 5" data-media="Offer Map" data-outcome="Outcome: build a sponsor and affiliate list that actually fits the viewer's intent." data-body="Map each content cluster to brands, software, books, services, and digital products that solve the same viewer problem. Premium monetization works best when the offer feels like the natural next step after the video.">
              <strong>5. Monetization</strong>
              <span>Design the revenue path.</span>
            </button>
          </aside>

          <article class="lesson-stage">
            <div class="lesson-feature">
              <div class="lesson-image" data-course-media>Team SOP Board</div>
              <div>
                <span class="eyebrow" data-course-kicker>Premium Chapter 1</span>
                <h2 data-course-title>Hiring and Team Roles</h2>
                <p class="lead" data-course-body>Treat the channel like a small editorial team. Define responsibilities, turnaround times, quality gates, file naming, revision rules, and who approves the final upload. Clear roles prevent missed details as volume increases.</p>
                <p class="notice" data-course-outcome>Outcome: create role cards for researcher, writer, voice artist, editor, thumbnail designer, and channel manager.</p>
              </div>
            </div>

            <div class="guide-body">
              <h2>Premium Operating Checks</h2>
              <div class="check-grid">
                <span>Yes: documented SOPs</span>
                <span>Yes: weekly analytics review</span>
                <span>Yes: creator-safe research sources</span>
                <span>No: unlicensed media reuse</span>
                <span>No: vague title promises</span>
                <span>No: scaling before quality control</span>
              </div>
            </div>
          </article>
        </div>
      </section>
    <?php endif; ?>
  </main>

  <div class="modal" id="premium-modal" role="dialog" aria-modal="true" aria-labelledby="premium-title">
    <div class="modal-panel">
      <h2 id="premium-title">Premium Access</h2>
      <p class="section-intro">Submit the exact details used for payment verification and the single-use key assigned by Star Labs.</p>
      <!-- Paystack payment link placeholder: paste verified Paystack checkout URL here. -->
      <form class="form-grid" method="post">
        <input type="hidden" name="action" value="premium_login">
        <label>Name <input name="name" required autocomplete="name"></label>
        <label>WhatsApp Number <input name="whatsapp" required inputmode="tel" autocomplete="tel"></label>
        <label>Email <input name="email" required type="email" autocomplete="email"></label>
        <label>Secret Key <input name="secret_key" required placeholder="starlabs-"></label>
        <div class="actions">
          <button class="btn gold" type="submit"><span class="crown-icon" aria-hidden="true">&#9819;</span> Unlock Guide</button>
          <button class="btn" type="button" data-modal-close>Close</button>
        </div>
      </form>
    </div>
  </div>

  <a class="btn primary floating-help" href="https://whatsapp.com/channel/0029Vb7Vhu8HwXbKCzWIWz04">Help</a>

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
  <script src="assets/app.js"></script>
</body>
</html>
