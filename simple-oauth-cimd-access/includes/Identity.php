<?php
namespace OCIMD;
final class Identity {
    private static function eligible(\WP_User $user): void {
        Support::need(empty($user->spam) && empty($user->deleted), 'account_blocked', 'The local account is marked as spam or deleted.');
    }
    public static function resolve(array $claims, array $s): \WP_User {
        $email = Policy::email(is_string($claims['email'] ?? null) ? $claims['email'] : '');
        [$allowed,$why] = Policy::test($s, $email, ($claims['email_verified'] ?? false) === true);
        Support::need($allowed, 'access_denied', $why);
        $issuer = $claims['iss']; $subject = $claims['sub'];
        return Store::locked('accounts', static function () use ($issuer,$subject,$email,$s) {
            global $wpdb; $table = $wpdb->prefix . 'ocimd_identities';
            $hash = hash('sha256', Support::json([$issuer,$subject]));
            $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE identity_hash=%s", $hash), ARRAY_A);
            if ($row) {
                Support::need($row['issuer'] === $issuer && $row['subject'] === $subject, 'identity_conflict', 'External identity is already linked to another account.');
                $user = get_user_by('id', $row['user_id']);
                Support::need($user instanceof \WP_User && is_user_member_of_blog($user->ID), 'account_missing', 'Linked local account is unavailable on this site.');
                self::eligible($user);
                return $user; // Never rematch or update account email/roles after the first link.
            }
            $new = false;
            // Query the shared users table so ambiguous email rows never resolve arbitrarily.
            $ids = $wpdb->get_col($wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE LOWER(user_email)=%s LIMIT 3", $email));
            Support::need(count($ids) <= 1, 'ambiguous_email', 'Multiple local accounts have this email; resolve the duplicate before login.');
            if ($ids) {
                $user = get_user_by('id', $ids[0]);
                Support::need($user instanceof \WP_User && is_user_member_of_blog($user->ID), 'account_missing', 'Matching local account is unavailable on this site.');
            } else {
                Support::need($s['create_users'], 'registration_disabled', 'No local account exists. Plugin registration is disabled.');
                $id = wp_insert_user(['user_login'=>'oidc_' . substr($hash,0,24),'user_pass'=>wp_generate_password(48,true,true),'user_email'=>$email,'display_name'=>explode('@',$email)[0],'role'=>'subscriber']);
                Support::need(!is_wp_error($id), 'account_create', 'Could not create the local subscriber account.');
                $user = get_user_by('id', $id); $new = true;
            }
            self::eligible($user);
            $binding = hash('sha256', Support::json([$issuer,(int)$user->ID]));
            $prior = $wpdb->get_var($wpdb->prepare("SELECT identity_hash FROM $table WHERE user_provider=%s", $binding));
            Support::need(!$prior, 'silent_relink', 'Account already has a different identity for this issuer. A changed proxy client ID may change pairwise subjects. Use authenticated unlink and link; email never replaces an existing identity.');
            $ok = $wpdb->insert($table, ['identity_hash'=>$hash,'issuer'=>$issuer,'subject'=>$subject,'user_id'=>$user->ID,'user_provider'=>$binding,'created_at'=>time()]);
            if ($ok !== 1) {
                // Keep a newly created, random-password account for safe administrator recovery; never guess a match.
                throw new Failure('identity_conflict', 'Identity binding could not be saved. An administrator must inspect the account before retrying.');
            }
            Support::audit($new ? 'account_created' : 'identity_linked', $user->ID);
            return $user;
        });
    }
    public static function unlink(int $user, string $hash): void {
        Store::locked('accounts', static function () use ($user,$hash) {
            global $wpdb;
            $wpdb->delete($wpdb->prefix . 'ocimd_identities', ['identity_hash'=>$hash,'user_id'=>$user]);
            Support::audit('identity_unlinked', $user);
        });
    }
    public static function forUser(int $id): array {
        global $wpdb;
        return $wpdb->get_results($wpdb->prepare("SELECT identity_hash,issuer,created_at FROM {$wpdb->prefix}ocimd_identities WHERE user_id=%d", $id), ARRAY_A);
    }
}
