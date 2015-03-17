# Autenticación

- [Introducción](#introduction)
- [Autenticando Usuarios](#authenticating-users)
- [Devolviendo El Usuario Autenticado](#retrieving-the-authenticated-user)
- [Protegiendo Rutas](#protecting-routes)
- [Autenticación Básica HTTP](#http-basic-authentication)
- [Recordatorios y Reseteo de Contraseña](#password-reminders-and-reset)
- [Autenticación Social](#social-authentication)

<a name="introduction"></a>
## Introducción

Laravel hace que implementar autenticación sea muy simple. De hecho, casi todo está configurado por ti fuera de la caja. El archivo de configuración de autenticación está localizado en `config/auth.php`, que contiene varias opciones bien documentadas para modificar el comportamiento de los servicios de autenticación.

Por defecto, Laravel incluye un modelo `App\User` en tu carpeta `app`. Este modelo puede ser usado con el driver de autenticación de Eloquent que viene por defecto.

 Recuerda: cuando construyas el esquema de base de datos para este modelo, haz que la columna de la contraseña tenga como mínimo 60 caracteres. También, antes de empezar, asegúrate que tu table `users` (o su equivalente) contenga una columna `remember_token` de tipo string que acepte valores nulos y sea de 100 caracteres. Esta columna será usada para almacenar un token para las sesiones que hayan marcado la opción "remember me" en tu aplicación. Esto puede ser hecho usando `$table->rememberToken();` en una migración. Por supuesto, ¡Laravel 5 tiene migraciones para estas columnas fuera de la caja!

Si tu aplicación no está usando Eloquent, puedes usar el driver de autenticación `database` que usa el constructor de pedidos de Laravel.

<a name="authenticating-users"></a>
## Autenticando Usuarios

Laravel viene con dos controladores relacionados a autenticación fuera de la caja. El controlador `AuthController` maneja el registro de nuevos usuarios y el "inicio de sesión", mientras que `PasswordController` contiene la lógica que ayuda a los usuarios existentes a resetear sus contraseñas olvidadas.

Cada uno de estos controladores usa un trait que incluye los métodos necesarios. Para muchas aplicaciones, no vas a necesitar modificar estos controladores. Las vistas que estos controladores renderizan están localizadas en la carpeta `resources/views/auth`. Eres libre de personalizar las vistas como desees.


### El Registro de Usuarios

Para modificar los campos del formulario que son requeridos para un nuevo registro de usuario en tu aplicación, debes modificar la clase `App\Services\Registrar`. Esta clase es responsable de la validación y la creación de nuevos usuarios en tu aplicación.

El método `validator` de `Registrar` contiene las reglas de validación para los nuevos usuarios de la aplicación, mientras que el método `create` de `Registrar` es responsable de crear nuevos registros de `User` en tu base de datos. Eres libre de modificar cada uno de estos métodos como desees. El `Registrar` es llamado por `AuthController` a través de los métodos contenidos en el trait `AuthenticatesAndRegistersUsers`.


#### Autenticación Manual

Si eliges no usar la implementación `AuthController`, vas a necesitar administrar la autenticación de tus usuarios usando las clases de autenticación de Laravel directamente. No te preocupes, ¡sigue siendo sencillo! Primero, revisemos el método `attempt`.

	<?php namespace App\Http\Controllers;

	use Auth;
	use Illuminate\Routing\Controller;

	class AuthController extends Controller {

		/**
		 * Handle an authentication attempt.
		 *
		 * @return Response
		 */
		public function authenticate()
		{
			if (Auth::attempt(['email' => $email, 'password' => $password]))
			{
				return redirect()->intended('dashboard');
			}
		}

	}

El método `attempt` acepta un arreglo de pares de llave / valor como primer argumento. El valor `password` va a ser [hasheado](/5.0/hashing). Los otros valores en el arreglo serán usados para encontrar al usuario en la tabla de tu base de datos. Así que, en el ejemplo de arriba, el usuario será devuelto a partir del valor de la columna `email`. Si el usuario es encontrado, la contraseña hasheada almacenada en la base de datos será comparada con el valor de `password` hasheado que ha sido pasado al método a través del arreglo. Si ambas contraseñas son iguales, una nueva sesión autenticada será iniciada para el usuario.

El método `attempt` devolverá `true` si la autenticación fue exitosa. De otra manera, `false` será devuelto.

> **Nota:** En este ejemplo, `email` no es una opción requerida, simplemente es usado como ejemplo. Deberías usar la columna que equivalga a un "nombre de usuario" en tu base de datos.

La función de redireción `intended` va a redirigir al usuario a la URL a la que intentaban acceder antes de ser capturado por el filtro de autenticación. Una URI por defecto puede ser dada a este método en caso que el destino no se encuentre disponible.


#### Authenticating A User With Conditions

You also may add extra conditions to the authentication query:

    if (Auth::attempt(['email' => $email, 'password' => $password, 'active' => 1]))
    {
        // The user is active, not suspended, and exists.
    }

#### Determining If A User Is Authenticated

To determine if the user is already logged into your application, you may use the `check` method:

	if (Auth::check())
	{
		// The user is logged in...
	}

#### Authenticating A User And "Remembering" Them

If you would like to provide "remember me" functionality in your application, you may pass a boolean value as the second argument to the `attempt` method, which will keep the user authenticated indefinitely, or until they manually logout. Of course, your `users` table must include the string `remember_token` column, which will be used to store the "remember me" token.

	if (Auth::attempt(['email' => $email, 'password' => $password], $remember))
	{
		// The user is being remembered...
	}

If you are "remembering" users, you may use the `viaRemember` method to determine if the user was authenticated using the "remember me" cookie:

	if (Auth::viaRemember())
	{
		//
	}

#### Authenticating Users By ID

To log a user into the application by their ID, use the `loginUsingId` method:

	Auth::loginUsingId(1);

#### Validating User Credentials Without Login

The `validate` method allows you to validate a user's credentials without actually logging them into the application:

	if (Auth::validate($credentials))
	{
		//
	}

#### Logging A User In For A Single Request

You may also use the `once` method to log a user into the application for a single request. No sessions or cookies will be utilized:

	if (Auth::once($credentials))
	{
		//
	}

#### Manually Logging In A User

If you need to log an existing user instance into your application, you may call the `login` method with the user instance:

	Auth::login($user);

This is equivalent to logging in a user via credentials using the `attempt` method.

#### Logging A User Out Of The Application

	Auth::logout();

Of course, if you are using the built-in Laravel authentication controllers, a controller method that handles logging users out of the application is provided out of the box.

#### Authentication Events

When the `attempt` method is called, the `auth.attempt` [event](/5.0/events) will be fired. If the authentication attempt is successful and the user is logged in, the `auth.login` event will be fired as well.

<a name="retrieving-the-authenticated-user"></a>
## Retrieving The Authenticated User

Once a user is authenticated, there are several ways to obtain an instance of the User.

First, you may access the user from the `Auth` facade:

	<?php namespace App\Http\Controllers;

	use Illuminate\Routing\Controller;

	class ProfileController extends Controller {

		/**
		 * Update the user's profile.
		 *
		 * @return Response
		 */
		public function updateProfile()
		{
			if (Auth::user())
			{
				// Auth::user() returns an instance of the authenticated user...
			}
		}

	}

Second, you may access the authenticated user via an `Illuminate\Http\Request` instance:

	<?php namespace App\Http\Controllers;

	use Illuminate\Http\Request;
	use Illuminate\Routing\Controller;

	class ProfileController extends Controller {

		/**
		 * Update the user's profile.
		 *
		 * @return Response
		 */
		public function updateProfile(Request $request)
		{
			if ($request->user())
			{
				// $request->user() returns an instance of the authenticated user...
			}
		}

	}

Thirdly, you may type-hint the `Illuminate\Contracts\Auth\Authenticatable` contract. This type-hint may be added to a controller constructor, controller method, or any other constructor of a class resolved by the [service container](/5.0/container):

	<?php namespace App\Http\Controllers;

	use Illuminate\Routing\Controller;
	use Illuminate\Contracts\Auth\Authenticatable;

	class ProfileController extends Controller {

		/**
		 * Update the user's profile.
		 *
		 * @return Response
		 */
		public function updateProfile(Authenticatable $user)
		{
			// $user is an instance of the authenticated user...
		}

	}

<a name="protecting-routes"></a>
## Protecting Routes

[Route middleware](/5.0/middleware) can be used to allow only authenticated users to access a given route. Laravel provides the `auth` middleware by default, and it is defined in `app\Http\Middleware\Authenticate.php`. All you need to do is attach it to a route definition:

	// With A Route Closure...

	Route::get('profile', ['middleware' => 'auth', function()
	{
		// Only authenticated users may enter...
	}]);

	// With A Controller...

	Route::get('profile', ['middleware' => 'auth', 'uses' => 'ProfileController@show']);

<a name="http-basic-authentication"></a>
## HTTP Basic Authentication

HTTP Basic Authentication provides a quick way to authenticate users of your application without setting up a dedicated "login" page. To get started, attach the `auth.basic` middleware to your route:

#### Protecting A Route With HTTP Basic

	Route::get('profile', ['middleware' => 'auth.basic', function()
	{
		// Only authenticated users may enter...
	}]);

By default, the `basic` middleware will use the `email` column on the user record as the "username".

#### Setting Up A Stateless HTTP Basic Filter

You may also use HTTP Basic Authentication without setting a user identifier cookie in the session, which is particularly useful for API authentication. To do so, [define a middleware](/5.0/middleware) that calls the `onceBasic` method:

	public function handle($request, Closure $next)
	{
		return Auth::onceBasic() ?: $next($request);
	}

If you are using PHP FastCGI, HTTP Basic authentication may not work correctly out of the box. The following lines should be added to your `.htaccess` file:

	RewriteCond %{HTTP:Authorization} ^(.+)$
	RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

<a name="password-reminders-and-reset"></a>
## Password Reminders & Reset

### Model & Table

Most web applications provide a way for users to reset their forgotten passwords. Rather than forcing you to re-implement this on each application, Laravel provides convenient methods for sending password reminders and performing password resets.

To get started, verify that your `User` model implements the `Illuminate\Contracts\Auth\CanResetPassword` contract. Of course, the `User` model included with the framework already implements this interface, and uses the `Illuminate\Auth\Passwords\CanResetPassword` trait to include the methods needed to implement the interface.

#### Generating The Reminder Table Migration

Next, a table must be created to store the password reset tokens. The migration for this table is included with Laravel out of the box, and resides in the `database/migrations` directory. So all you need to do is migrate:

	php artisan migrate

### Password Reminder Controller

Laravel also includes an `Auth\PasswordController` that contains the logic necessary to reset user passwords. We've even provided views to get you started! The views are located in the `resources/views/auth` directory. You are free to modify these views as you wish to suit your own application's design.

Your user will receive an e-mail with a link that points to the `getReset` method of the `PasswordController`. This method will render the password reset form and allow users to reset their passwords. After the password is reset, the user will automatically be logged into the application and redirected to `/home`. You can customize the post-reset redirect location by defining a `redirectTo` property on the `PasswordController`:

	protected $redirectTo = '/dashboard';

> **Note:** By default, password reset tokens expire after one hour. You may change this via the `reminder.expire` option of your `config/auth.php` file.

<a name="social-authentication"></a>
## Social Authentication

In addition to typical, form based authentication, Laravel also provides a simple, convenient way to authenticate with OAuth providers using [Laravel Socialite](https://github.com/laravel/socialite). **Socialite currently supports authentication with Facebook, Twitter, Google, GitHub and Bitbucket.**

To get started with Socialite, include the package in your `composer.json` file:

	"laravel/socialite": "~2.0"

Next, register the `Laravel\Socialite\SocialiteServiceProvider` in your `config/app.php` configuration file. You may also register a [facade](/5.0/facades):

	'Socialize' => 'Laravel\Socialite\Facades\Socialite',

You will need to add credentials for the OAuth services your application utilizes. These credentials should be placed in your `config/services.php` configuration file, and should use the key `facebook`, `twitter`, `google`, or `github`, depending on the providers your application requires. For example:

	'github' => [
		'client_id' => 'your-github-app-id',
		'client_secret' => 'your-github-app-secret',
		'redirect' => 'http://your-callback-url',
	],

Next, you are ready to authenticate users! You will need two routes: one for redirecting the user to the OAuth provider, and another for receiving the callback from the provider after authentication. Here's an example using the `Socialize` facade:

	public function redirectToProvider()
	{
		return Socialize::with('github')->redirect();
	}

	public function handleProviderCallback()
	{
		$user = Socialize::with('github')->user();

		// $user->token;
	}

The `redirect` method takes care of sending the user to the OAuth provider, while the `user` method will read the incoming request and retrieve the user's information from the provider. Before redirecting the user, you may also set "scopes" on the request:

	return Socialize::with('github')->scopes(['scope1', 'scope2'])->redirect();

Once you have a user instance, you can grab a few more details about the user:

#### Retrieving User Details

	$user = Socialize::with('github')->user();

	// OAuth Two Providers
	$token = $user->token;

	// OAuth One Providers
	$token = $user->token;
	$tokenSecret = $user->tokenSecret;

	// All Providers
	$user->getId();
	$user->getNickname();
	$user->getName();
	$user->getEmail();
	$user->getAvatar();
