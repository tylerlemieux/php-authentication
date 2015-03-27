<?php
	/**
	 * API for creating user salts, hashes, and authenticating a user 
	 * from a database
	 *
	 * REQUIRES TABLE FOR USERS WITH: UserID (PK AutoIncrement)
	 * Username, Password, Salt
	 * Column names do not matter, but they must be passed into the function
	 *
	 * @author     Tyler Lemieux <lemex2004@gmail.com>
	 * @copyright  2015 Tyler Lemieux
	 */

	/**
	 * This class holds the database connection and user table info
	 * and has functions to create salts hashes and authenticate
	 */
	class Authentication
	{
		private $dbConnection;
		private $userTableName;
		private $saltColName;
		private $passwordColName;
		private $usernameColName;
		private $userIdColName;

		/**
		 * This function takes in a connection and table and authenticates a user
		 * based on the salting in the database
		 *
		 * @param $dbConn - mysqli_connection
		 * @param $userTable is a UserTable containing column info
		 */
		function __construct($dbConn, $userTable)
		{
			//Check the dbConnection passed in is valid then set it
			$this->dbConnection = $dbConn;

			if(isset($userTable->userTableName) && 
				isset($userTable->saltColumnName) && 
				isset($userTable->passwordColumnName) && 
				isset($userTable->usernameColumnName) &&
				isset($userTable->userIdColName))
			{
				$this->userTableName = $userTable->userTableName;
				$this->saltColName = $userTable->saltColumnName;
				$this->passwordColName = $userTable->passwordColumnName;
				$this->usernameColName = $userTable->usernameColumnName;
				$this->userIdColName = $userTable->userIdColName;
			}
		}

		/**
		 * Creates a new user 
		 *
		 * @param $username - username of user
		 * @param $password - password of user
		 *
		 * @return userId
		 */
		public function createUser($username, $password)
		{
			$salt = generateRandomSaltKey();
			$passwordWithSalt = $password.$salt;
			$hashedPass = hash('sha512', $passwordWithSalt);

			//Insert into the database
			$stmt = $this->dbConnection->prepare("INSERT INTO ? (?, ?, ?) VALUES (?, ?, ?)");
			$stmt->bind_param("sssssss", $this->userTableName, $this->usernameColName, $this->passwordColName, $this->saltColName, $username, $hashedPass, $salt);
			$stmt->execute();

			//Get the inserted user id and return it
			$userId = $stmt->insert_id;
			return $userId;
		}

		/**
		 * Generates a salt 
		 * @return salt
		 */
		private function generateRandomSaltKey()
		{
			$salt = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);;
			return $salt;
		}

		/**
		 * Authenticate user
		 *
		 * @param $username - username to check
		 * @param $password - password to check
		 *
		 * @return userid if exists, -1 if user doesnt exist
		 */
		public function authenticate($username, $password)
		{
			//Query to get the salt for the desired username
			$stmt = $this->dbConnection->prepare("SELECT ? FROM ? WHERE ? = ?");
			$stmt->bind_param("ssss", $this->saltColName, $this->tableName, $this->usernameColName, $username);
			$stmt->execute();
			$result = $stmt->get_result();
			$numRows = $result->num_rows;
			if($numRows > 0)
			{
				//If the username exists, get the salt and add it to the password
				$row = $result->fetch_array();
				$salt = $row[0];
				$hashedPass = hash('sha512', $password.$salt);

				//Query to see if the salted and hashed username pass combo exists
				$stmt = $this->dbConnection->prepare("SELECT ? FROM ? WHERE ?=? AND ?=?");
				$stmt->bind_param("ssssss", $this->userIdColName, $this->userTableName, $this->usernameColName, $username, $this->passwordColumnName, $password);
				$stmt->execute();
				$result = $stmt->get_result();

				//Check the number of rows
				//If there is a row that was found return the id, else return -1				
				$userNumRows = $result->num_rows;
				if($userNumRows > 0)
				{
					$row = $result->fetch_array();
					$userId = $row[0];
				}
				return $userNumRows > 0 ? $userId : -1;
			}
			else
			{
				return -1;
			}
		}
	}

	/**
	 * Class for holding data about the table being used to authenticate against
     */
	class UserTable
	{
		public $userTableName;
		public $saltColumnName;
		public $passwordColumnName;
		public $usernameColumnName;
		public $userIdColName;

		/**
		 * Construct for UserTable class.  Initializes data into the class 
		 * to allow a user to easily pass it into the authentication class
		 *
		 * @param $userTableName - name of the user table
		 * @param $saltColName - name of the salt column
		 * @param $passColName - name of the password column
		 * @param $usernameColName - name of the username column
		 * @param $userIdColName - name of the user id column
		 */
		function __construct($userTableName, $saltColName, $passColName, $usernameColName, $userIdColName)
		{
			$this->userTableName = $userTableName;
			$this->saltColumnName = $saltColName;
			$this->passwordColumnName = $passColName;
			$this->usernameColumnName = $usernameColName;
			$this->userIdColName = $userIdColName;
		}
	}


?>
