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
        return Store::locked('accounts', static function () use ($email,$s) {
            global $wpdb;
            // WordPress does not enforce unique email addresses at the database level.
            $ids = $wpdb->get_col($wpdb->prepare('SELECT ID FROM %i WHERE LOWER(user_email)=%s LIMIT 3', $wpdb->users, $email));
            Support::need(count($ids) <= 1, 'ambiguous_email', 'Multiple local accounts have this email; resolve the duplicate before login.');
            if ($ids) {
                $user = get_user_by('id', $ids[0]);
                Support::need($user instanceof \WP_User && is_user_member_of_blog($user->ID), 'account_missing', 'Matching local account is unavailable on this site.');
                self::eligible($user);
                return $user;
            }
            Support::need($s['create_users'], 'registration_disabled', 'No local account exists. Plugin registration is disabled.');
            $id = wp_insert_user(['user_login'=>'soca_' . substr(hash('sha256', $email),0,24),'user_pass'=>wp_generate_password(48,true,true),'user_email'=>$email,'role'=>'subscriber']);
            Support::need(!is_wp_error($id), 'account_create', 'Could not create the local subscriber account.');
            $user = get_user_by('id', $id);
            Support::need($user instanceof \WP_User, 'account_create', 'The created local account could not be loaded.');
            self::eligible($user);
            Support::audit('account_created', $user->ID);
            return $user;
        });
    }
}
