<?php
/**
 * Library for the password
 *
 * Features and advantages
 *   * Quality checking (complexity) password
 *   * Generation of high-quality and resistant to cracking password
 *   * A method that returns derivatives from the password to be able to log in (authorization),
 *     regardless of keyboard layout (language input) and pressing [Caps Lock] or [Shift] buttons.
 *     Security remark
 *       The method returns the only a few password forms for a successful log in (authorization) possibility.
 *       It's too little against the billions combinations of high-quality passwords.
 *       However, the usefulness of this feature may be condemned by some critics.
 *
 * Example (derivatives of password)
 *   en, [Caps Lock] off: abCD1%
 *   en, [Caps Lock] on:  ABcd1%
 *   ru, [Caps Lock] off: фиСВ1%
 *   ru, [Caps Lock] on:  ФИсв1%
 *
 * History
 *   This class has been used successfully in August 2009 in several commercial projects
 *
 * TODO
 *   http://ru.wikipedia.org/wiki/Раскладка_клавиатуры
 *
 * Useful links
 *   http://allanguages.info/
 *
 * @link     http://code.google.com/p/php-password/
 * @license  http://creativecommons.org/licenses/by-sa/3.0/
 * @author   Nasibullin Rinat
 * @version  1.1.0
 */
class Password
{
	const ALNUM = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

	#calling the methods of this class only statically!
	private function __construct() {}

	/**
	 * Quality checking (complexity) password
	 *
	 * Bad passwords
	 *   * length < 6 or > 20 characters
	 *   * characters beyond the range of \x20-\x7e
	 *     (non-ASCII can not be used because this can cause problems with charsets)
	 *   * does not contain both letters and numbers
	 *   * sequence of characters as the keyboard (123456, qwerty)
	 *   * halves, as on a keyboard (qazxsw), repeated (werwer, 12,341,234) and
	 *     "reflected" (123 321, qweewq) sequences are included here
	 *   * unique characters less than 46 % (wwwfff, 000000)
	 *
	 * За основу был взят оригинальный скрипт Tronyx (http://forum.dklab.ru/viewtopic.php?t=7014),
	 * который был модифицирован и улучшен.
	 *
	 * @param   string  $password          Password
	 * @param   bool    $is_check_digits   Check for the numbers exists?
	 * @param   bool    $is_check_letters  Check for the latin letters exists?
	 * @return  bool                       TRUE, if the password is good and FALSE,
	 *                                     if the password is weak or error occurred
	 */
	public static function quality_check($password, $is_check_digits = true, $is_check_letters = true)
	{
		if (! ReflectionTypeHint::isValid()) return false;

		#проверка минимальной длины и допустимых символов
		if (! preg_match('/^[\x20-\x7e]{6,20}$/sSX', $password)) return false;

		#проверка на цифры
		if ($is_check_digits && ! preg_match('/\d/sSX', $password)) return false;

		#проверка на латинские буквы
		if ($is_check_letters && ! preg_match('/[a-zA-Z]/sSX', $password)) return false;

		#последовательность символов как на клавиатуре (123456, qwerty, qazwsx, abcdef)
		$chars = '`1234567890-=\\'.  #второй ряд клавиш, [Shift] off
			'~!@#$%^&*()_+|'.   #второй ряд клавиш, [Shift] on
			'qwertyuiop[]asdfghjkl;\'zxcvbnm,./'.  #по горизонтали (расшир. диапазон)
			'QWERTYUIOP{}ASDFGHJKL:"ZXCVBNM<>?'.   #по горизонтали (расшир. диапазон)
			'qwertyuiopasdfghjklzxcvbnm'.  #по горизонтали
			'QWERTYUIOPASDFGHJKLZXCVBNM'.  #по горизонтали
			'qazwsxedcrfvtgbyhnujmikolp'.  #по диагонали
			'QAZWSXEDCRFVTGBYHNUJMIKOLP'.  #по диагонали
			'abcdefghijklmnopqrstuvwxyz'.  #по алфавиту
			'ABCDEFGHIJKLMNOPQRSTUVWXYZ';  #по алфавиту

		if (strpos($chars, $password)         !== false) return false;
		if (strpos($chars, strrev($password)) !== false) return false;

		$length = strlen($password);

		#половинки, как на клавиатуре (повторные и "отражённые" последовательности сюда включаются)
		if ($length > 5 && $length % 2 == 0)
		{
			$c = $length / 2;
			$left  = substr($password, 0, $c);  #первая половина пароля
			$right = substr($password, $c);     #вторая половина пароля

			$is_left  = (strpos($chars, $left)  !== false or strpos($chars, strrev($left))  !== false);
			$is_right = (strpos($chars, $right) !== false or strpos($chars, strrev($right)) !== false);

			if ($is_left && $is_right) return false;
		}

		#процент уникальности символов
		$k = strlen(count_chars($password, 3)) / $length;
		if ($k < 0.46) return false;

		return true;
	}

	/**
	 * Generates high-quality and resistant to cracking password
	 *
	 * @param    int|digit  $length   Length of the string output
	 * @param    string     $chars    Alphabet to create a pseudorandom string
	 *                                by default [2-9a-zA-NP-Z]
	 *                                (Except 0O1l, because these letters and numbers are difficult to discern visually)
	 * @return   string|bool          Returns FALSE if error occurred
	 */
	public static function generate($length = 8, $chars = '23456789abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ')
	{
		if (! ReflectionTypeHint::isValid()) return false;

		#36 ^ 6 = 2 176 782 336 unique combinations minimum
		if ($length < 6)
		{
			trigger_error('Minimum length of password is 6 chars, ' . $length . ' given!', E_USER_WARNING);
			return false;
		}
		$chars = count_chars($chars, $mode = 3); #gets unique chars
		$len = strlen($chars);
		if ($len < 36)
		{
			trigger_error('Minimum length of alphabet chars is 36 unique chars (e. g. [a-z\d] in regexp terms), ' . $len . ' given!', E_USER_WARNING);
			return false;
		}

		mt_srand((double)microtime() * 1000000);  #initialize
		$c = 0;
		do
		{
			for ($password = '', $i = 0; $i < $length; $i++) $password .= substr($chars, mt_rand(0, $len - 1), 1);
			$c++;
			if ($c > 100)
			{
				#protects for endless cycle
				trigger_error('Endless cycle found!', E_USER_WARNING);
				return false;
			}
		}
		while (! self::quality_check($password));
		return $password;
	}

	/**
	 * Returns derivatives from the password to be able to log in (authorization),
	 * regardless of keyboard layout (language input) and pressing [Caps Lock] or [Shift] buttins.
	 * Character encoding — UTF-8.
	 *
	 * @param   string         $password    Password
	 * @param   string         $lang        Language
	 * @return  array|bool                  A few password forms
	 *                                      Returns FALSE if error occurred
	 */
	public static function keyboard_forms($password, $lang = 'ru')
	{
		if (! ReflectionTypeHint::isValid()) return false;

		$passwords = array(
			//$password,
			self::_keyboard_layout_conv($password, $lang, 'en'),
			self::_keyboard_layout_conv($password, 'en', $lang),
		);

		for ($c = count($passwords), $i = 0; $i < $c; $i++)
			$passwords[] = self::_keyboard_capslock_invert($passwords[$i]);

		return $passwords;
	}

	/**
	 * Converts lowercase characters to uppercase and vice versa.
	 *
	 * @param    string   $s
	 * @return   string
	 */
	private static function _keyboard_capslock_invert($s)
	{
		$trans = UTF8::$convert_case_table;
		$trans += array_flip($trans);
		return strtr($s, $trans);
	}

	/**
	 * Converts text from one keyboard to another.
	 * Character encoding - UTF-8.
	 *
	 * Globalize your On Demand Business: logical keyboard layout registry index
	 * Keyboard layouts for countries and regions around the world.
	 * http://www-306.ibm.com/software/globalization/topics/keyboards/registry_index.jsp
	 *
	 * @param   string   $s       Text in UTF-8
	 * @param   string   $input   Input keyboard layout (en, ru)
	 * @param   string   $output  Output keyboard layout (en, ru)
	 * @return  string|bool       String on success, FALSE on error
	 */
	private static function _keyboard_layout_conv($s, $input, $output)
	{
		#QWERTY раскладка клавиатуры для русского и английского языка
		static $trans_en_ru = array(
			#[CapsLock] off
			'`' => 'ё',
			'q' => 'й',
			'w' => 'ц',
			'e' => 'у',
			'r' => 'к',
			't' => 'е',
			'y' => 'н',
			'u' => 'г',
			'i' => 'ш',
			'o' => 'щ',
			'p' => 'з',
			'[' => 'х',
			']' => 'ъ',
			'a' => 'ф',
			's' => 'ы',
			'd' => 'в',
			'f' => 'а',
			'g' => 'п',
			'h' => 'р',
			'j' => 'о',
			'k' => 'л',
			'l' => 'д',
			';' => 'ж',
			'\'' => 'э',
			'z' => 'я',
			'x' => 'ч',
			'c' => 'с',
			'v' => 'м',
			'b' => 'и',
			'n' => 'т',
			'm' => 'ь',
			',' => 'б',
			'.' => 'ю',
			'/' => '.',

			#[CapsLock] on
			'~' => 'Ё',
			'@' => '"',
			'#' => '№',
			'$' => ';',
			'^' => ':',
			'&' => '?',
			'|' => '/',
			'Q' => 'Й',
			'W' => 'Ц',
			'E' => 'У',
			'R' => 'К',
			'T' => 'Е',
			'Y' => 'Н',
			'U' => 'Г',
			'I' => 'Ш',
			'O' => 'Щ',
			'P' => 'З',
			'{' => 'Х',
			'}' => 'Ъ',
			'A' => 'Ф',
			'S' => 'Ы',
			'D' => 'В',
			'F' => 'А',
			'G' => 'П',
			'H' => 'Р',
			'J' => 'О',
			'K' => 'Л',
			'L' => 'Д',
			':' => 'Ж',
			'"' => 'Э',
			'Z' => 'Я',
			'X' => 'Ч',
			'C' => 'С',
			'V' => 'М',
			'B' => 'И',
			'N' => 'Т',
			'M' => 'Ь',
			'<' => 'Б',
			'>' => 'Ю',
			'?' => ',',
		);
		if ($input === 'en' && $output === 'ru') return strtr($s, $trans_en_ru);
		if ($input === 'ru' && $output === 'en') return strtr($s, array_flip($trans_en_ru));
		trigger_error('Unsupported input and output keyboard layouts!', E_USER_WARNING);
		return false;
	}
}