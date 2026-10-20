<?php
namespace SOCA;
final class Identity {
    private static function eligible(\WP_User $user): void {
        Support::need(empty($user->spam) && empty($user->deleted), 'account_blocked', 'The local account is marked as spam or deleted.');
        Support::need(is_user_member_of_blog($user->ID) && $user->exists() && (bool)$user->roles && $user->has_cap('read'), 'account_missing', 'The linked local account has no access to this site.');
    }
    private static function key(string $issuer, string $subject): string {
        Http::url($issuer);
        Support::need($subject !== '' && strlen($subject) <= 255 && !preg_match('/[^\x20-\x7e]/', $subject), 'subject', 'Enter the exact OIDC subject, 1–255 ASCII bytes.');
        return 'soca_link_' . hash('sha256', Support::json([$issuer,$subject]));
    }
    /** Called only after an authorised local administrator approves the exact identity. */
    public static function link(int $userId, string $issuer, string $subject): void {
        Store::locked('accounts', static function () use ($userId,$issuer,$subject) {
            $key = self::key($issuer,$subject); $old = get_option($key);
            $user = get_user_by('id', $userId);
            Support::need($user instanceof \WP_User, 'account_missing', 'The local account does not exist.'); self::eligible($user);
            if ($old) {
                $previous = Store::open($old);
                if (empty($previous['revoked'])) {
                    Support::need($previous['user'] === $userId, 'identity_conflict', 'This identity is already linked to another account. Unlink it explicitly first.');
                    return;
                }
                Support::need(update_option($key, Store::seal(['issuer'=>$issuer,'subject'=>$subject,'user'=>$userId]), false), 'identity_conflict', 'The revoked identity could not be approved.');
                Support::audit('identity_linked', $userId); return;
            }
            Support::need(add_option($key, Store::seal(['issuer'=>$issuer,'subject'=>$subject,'user'=>$userId]), '', false), 'identity_conflict', 'The identity was linked concurrently.');
            Support::audit('identity_linked', $userId);
        });
    }
    public static function unlink(int $userId, string $issuer, string $subject): void {
        Store::locked('accounts', static function () use ($userId,$issuer,$subject) {
            $key = self::key($issuer,$subject); $old = get_option($key);
            Support::need(is_string($old) && Store::open($old)['user'] === $userId, 'identity_conflict', 'The specified account does not own this link.');
            Support::need(update_option($key, Store::seal(['issuer'=>$issuer,'subject'=>$subject,'user'=>$userId,'revoked'=>true]), false), 'identity_conflict', 'The identity link could not be revoked.');
            \WP_Session_Tokens::get_instance($userId)->destroy_all();
            Settings::invalidate();
            Support::audit('identity_unlinked', $userId);
        });
    }
    public static function resolve(array $claims, array $s): \WP_User {
        $email = Policy::email(is_string($claims['email'] ?? null) ? $claims['email'] : '');
        [$allowed,$why] = Policy::test($s, $email, ($claims['email_verified'] ?? false) === true);
        Support::need($allowed, 'access_denied', $why);
        Support::need(($claims['iss'] ?? null) === $s['issuer'], 'issuer', 'Identity issuer does not match this profile.');
        $key = self::key($s['issuer'], Support::scalar($claims, 'sub'));
        return Store::locked('accounts', static function () use ($email,$s,$key,$claims) {
            $sealed = get_option($key);
            if ($sealed) {
                $link = Store::open($sealed);
                Support::need(empty($link['revoked']), 'identity_revoked', 'This identity was unlinked. Administrator approval is required before reuse.');
                $user = get_user_by('id', $link['user']);
                Support::need($user instanceof \WP_User, 'account_missing', 'The linked account was removed. Administrator recovery is required.');
                self::eligible($user); return $user;
            }
            // Email can suggest an account, but cannot establish ownership of it.
            $ids = get_users(['search'=>$email, 'search_columns'=>['user_email'], 'fields'=>'ID', 'number'=>3, 'blog_id'=>0]);
            Support::need(count($ids) <= 1, 'ambiguous_email', 'Multiple local accounts have this email; resolve the duplicate before linking.');
            Support::need(!$ids, 'identity_unlinked', 'This identity needs an administrator-approved link to the existing account.');
            Support::need($s['create_users'], 'registration_disabled', 'No linked account exists. Plugin registration is disabled.');
            $id = wp_insert_user(['user_login'=>'soca_' . substr(hash('sha256', $key),0,24),'user_pass'=>wp_generate_password(48,true,true),'user_email'=>$email,'role'=>'subscriber']);
            Support::need(!is_wp_error($id), 'account_create', 'Could not create the local subscriber account.');
            try {
                $user = get_user_by('id', $id);
                Support::need($user instanceof \WP_User, 'account_create', 'The created local account could not be loaded.'); self::eligible($user);
                Support::need(add_option($key, Store::seal(['issuer'=>$s['issuer'],'subject'=>$claims['sub'],'user'=>(int)$id]), '', false), 'identity_conflict', 'The identity was linked concurrently.');
            } catch (\Throwable $e) {
                require_once ABSPATH . 'wp-admin/includes/user.php';
                if (is_multisite()) { require_once ABSPATH . 'wp-admin/includes/ms.php'; wpmu_delete_user((int)$id); }
                else { wp_delete_user((int)$id); }
                throw $e;
            }
            Support::audit('account_created', (int)$id); Support::audit('identity_linked', (int)$id);
            return $user;
        });
    }
}
