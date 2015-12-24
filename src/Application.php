<?php
/**
 * Created by PhpStorm.
 * User: nazarenko
 * Date: 20.10.2014
 * Time: 11:43
 */
namespace samsoncms\app\signin;

use samson\activerecord\dbQuery;
use samson\social\email\EmailStatus;
use samsonphp\event\Event;
use samsonframework\orm\QueryInterface;
use samson\social\email\Email;

/**
 * Generic class for user sign in
 * @author Olexandr Nazarenko <nazarenko@samsonos.com>
 * @copyright 2014 SamsonOS
 */
class Application extends \samson\core\CompressableExternalModule
{
    /** @var string Identifier */
    public $id = 'cms-signin';

    /** @var Email Pointer to social email module */
    protected $social;

    /** @var QueryInterface Databvase query instance */
    protected $query;

    public function authorize($social)
    {
        if (m('cms')->isCMS()) {
            if ($social->id == 'socialemail') {
                if (!m('social')->authorized()) {
                    if (!m('socialemail')->cookieVerification()) {
                        if (!url()->is('cms-signin')) {
                            url()->redirect('/cms/signin');
                        }
                    } else {
                        url()->redirect('/cms/signin');
                    }
                } else {
                    if (url()->is('cms-signin')) {
                        url()->redirect('/cms');
                    }
                }
            }
        }
    }

    /**
     * Application constructor.
     *
     * @param string $path
     * @param null $vid
     * @param null $resources
     */
    public function  __construct($path, $vid = null, $resources = NULL )
    {
        // Inject dependencies
        $this->social = m('socialemail');
        $this->query = new dbQuery();

        parent::__construct($path, $vid, $resources);
    }

    //[PHPCOMPRESSOR(remove,start)]
    /** Module preparation */
    public function prepare()
    {
        // Create default user for first logins
        $adminUser = 'admin@admin.com';
        $hashedEmailValue = $this->social->hash($adminUser);

        // Try to find generic user
        $admin = $this->query
            ->entity($this->social->dbTable)
            ->where($this->social->dbEmailField, $adminUser)
            ->first();

        // Create user record if missing
        if (!isset($admin)) {
             $admin = new $this->social->dbTable();
        }

        // Fill in user credentials according to config
        $admin[$this->social->dbEmailField] = $adminUser;
        $admin[$this->social->dbHashEmailField] = $hashedEmailValue;
        $admin[$this->social->dbHashPasswordField] = $hashedEmailValue;
        $admin->save();
    }
    //[PHPCOMPRESSOR(remove,end)]

    /** Check the user's authorization */
    public function __HANDLER()
    {
        $this->authorize($this->social);
    }

    /** Main sign in template */
    public function __base()
    {
        // Change template
        s()->template('www/signin/signin_template.vphp');

        // Render template with sign in form
        $this->html($this->view('www/signin/signin_form.vphp')->output())
            ->title(t('Авторизация', true));
    }

    /** User asynchronous sign in */
    public function __async_login()
    {
        $user = null;
        $error = '';

        if (isset($_POST['email']) && isset($_POST['password'])) {
            $email = $this->social->hash($_POST['email']);
            $password = $this->social->hash($_POST['password']);
            $remember = isset($_POST['remember']) ? true : false;

            /** @var EmailStatus Perform email authorization */
            $auth = $this->social->authorizeWithEmail($email, $password, $remember, $user);

            if ($auth->code === EmailStatus::SUCCESS_EMAIL_AUTHORIZE) {
                // Fire login success event
                Event::fire('samson.cms.signin.login', array(&$user));

                return array('status' => '1');
            } else {
                $error .= $this->view('www/signin/signin_form.vphp')
                    ->errorClass('errorAuth')
                    ->userEmail("{$_POST['email']}")
                    ->focus('autofocus')
                    ->output();

                return array('status' => '0', 'html' => $error);
            }
        } else {
            $error .= $this->view('www/signin/signin_form')->errorClass('errorAuth')->output();
            return array('status' => '0', 'html' => $error);
        }
    }

    /** User logout */
    public function __logout()
    {
        $this->social->deauthorize();

        // Fire logout event
        Event::fire('samson.cms.signin.logout');

        url()->redirect('cms/signin');
    }

    /** Sending email with the correct address */
    public function __mail()
    {
        if (isset($_POST['email'])) {
            /** @var \samson\activerecord\user $user */
            $user = null;
            $result = '';
            if (dbQuery('user')->where('email', $_POST['email'])->first($user)) {
                $user->confirmed = $this->social->hash(generate_password(20) . time());
                $user->save();
                $message = $this->view('www/signin/email/pass_recovery')->code($user->confirmed)->output();

                mail_send($user->Email, 'info@samsonos.com', $message, t('Восстановление пароля!', true), 'SamsonCMS');

                $result .= $this->view('www/signin/pass_recovery_mailsend')->output();
                s()->template('www/signin/signin_template.vphp');
                $this->html($result)->title(t('Восстановление пароля', true));
            } else {
                url()->redirect();
            }
        } else {
            url()->redirect();
        }
    }

    /**
     * New password form.
     *
     * @param string $code Code password recovery
     */
    public function __confirm($code)
    {
        if (dbQuery('user')->where($this->social->dbConfirmField, $code)->first()) {
            $result = '';
            $result .= m()->view('www/signin/new_pass_form')->code($code)->output();
            s()->template('www/signin/signin_template.vphp');
            m()->html($result)->title(t('Восстановление пароля', true));
        } else {
            return A_FAILED;
        }
    }

    /**
     * Setting new password and sign in
     * @param string $code Code password recovery
     */
    public function __recovery($code)
    {
        if (isset($_POST['password']) && isset($_POST['confirm_password'])
            && $_POST['password'] == $_POST['confirm_password']
        ) {
            /** @var \samson\activerecord\user $user */
            $user = null;
            if (dbQuery('user')->confirmed($code)->first($user)) {
                $user->confirmed = 1;
                $user->md5_password = md5($_POST['password']);
                $user->Password = $_POST['password'];
                $user->save();
                if (m('socialemail')->authorizeWithEmail($user->md5_email, $user->md5_password, $user)
                        ->code == EmailStatus::SUCCESS_EMAIL_AUTHORIZE
                ) {
                    url()->redirect();
                }
            }
        } else {
            $result = '';
            $result .= m()->view('www/signin/pass_error')
                ->message(t('Вы ввели некорректный пароль либо пароли не совпадают', true))
                ->output();
            s()->template('www/signin/signin_template.vphp');
            m()->html($result)->title(t('Ошибка восстановление пароля', true));
        }
    }
}
