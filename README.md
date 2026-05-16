# YouTube Automation Courses CMS

Professional light-theme CMS built with HTML5, CSS3, vanilla JavaScript, PHP, and Supabase PostgreSQL.

## Files

- `index.html` - landing page with hero, course overview, and navigation.
- `guides.html` - beginners guide with realistic YouTube automation content, templates, and thumbnails.
- `premium-guide.php` - protected premium guide using assigned single-use `starlabs-...` keys.
- `admin.php` - admin dashboard for content, key generation, premium onboarding, admin management, and audit logs.
- `supabase.php` - shared Supabase REST helper, audit insert function, key generator, and 7-minute session timeout.
- `database.sql` - Supabase table schema for `audit_logs`, `admins`, `secret_keys`, `premium_users`, and `course_content`.

## Setup

1. Run `database.sql` in the Supabase SQL editor.
2. In `supabase.php`, replace `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.
3. In `database.sql`, replace the sample admin password hash with a real value from PHP `password_hash()`.
4. In `admin.php`, keep `ADMIN_PRIME_ID` aligned with the primary admin row in Supabase.
5. In `premium-guide.php`, replace the Paystack placeholder comment with your verified payment link.

The code blocks DELETE and UPDATE operations targeting `ADMIN_PRIME_ID`, logs admin actions to `audit_logs`, and marks premium keys as used after successful onboarding or premium access.
