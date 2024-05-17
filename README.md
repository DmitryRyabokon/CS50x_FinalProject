# My Chat - Simple Messenger Web Application
#### Video Demo: https://youtu.be/KDZBCBZpLVM

#### Description:
The Simple Messenger Web Application is my final project for the CS50x course. This project is a web-based messaging application built using Flask and SQLite. The application allows users to register, log in, change their password, and text other users.

### Project Structure
- **app.py**: This is the main application file that sets up the Flask app, routes, and handles the server logic. It includes routes for the home page, login, registration, changing passwords, error handling, and messaging functionalities.
- **helpers.py**: Contains the `login_required` function that I borrowed from the CS50 finance project.
- **templates/**: This directory contains all HTML files used in the project. Key files include:
  - **index.html**: The main page with the chat window and input form to send messages.
  - **login.html**: The login page.
  - **register.html**: The registration page.
  - **change_password.html**: The page for changing passwords.
  - **apology.html**: Dynamically shows different error messages based on the message.
- **static/**: This directory contains static files such as CSS. Key files include:
  - **styles.css**: The main stylesheet for the application.
- **database.db**: This is the SQLite database file where all user data and messages are stored.

### Design Choices
When designing the application, I had to make several important decisions:

1. **Framework and Database**: I chose Flask and SQLite because I learned how to use them in the course's pset9 project. Their simplicity and effectiveness for small to medium-sized projects made them ideal for this application.

2. **User Authentication**: Implementing secure user authentication was a priority. I used hashing to store passwords securely and implemented session management to keep users logged in. This ensures user data is protected and only accessible to authenticated users.

3. **Messaging System**: For the messaging system, I used the Socket.IO library to enable real-time communication. This library allowed me to implement a responsive and interactive chat experience for users.

4. **UI/UX Design**: Creating a user-friendly interface was important. I used Bootstrap for responsive design and ensured the application works well on both desktop and mobile devices. This helps provide a consistent and pleasant user experience across different platforms.