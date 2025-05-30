<!DOCTYPE html>
<html>

<head>
  <title>Medical Guide</title>
  <meta name="keywords" content="" />
  <meta name="description" content="" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, user-scalable=no" />
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

  <link rel="icon" type="image/png" href="images/image-16x16.jpg" />

  <!--main file-->
  <link href="css/medical-guide.css" rel="stylesheet" type="text/css" />

  <!--Medical Guide Icons-->
  <link
    href="fonts/medical-guide-icons.css"
    rel="stylesheet"
    type="text/css" />

  <!-- Default Color-->
  <link
    href="css/default-color.css"
    rel="stylesheet"
    id="color"
    type="text/css" />

  <!--bootstrap-->
  <link href="css/bootstrap.css" rel="stylesheet" type="text/css" />

  <!--Dropmenu-->
  <link href="css/dropmenu.css" rel="stylesheet" type="text/css" />

  <!--Sticky Header-->
  <link href="css/sticky-header.css" rel="stylesheet" type="text/css" />

  <!--revolution-->
  <link href="css/style.css" rel="stylesheet" type="text/css" />
  <link href="css/settings.css" rel="stylesheet" type="text/css" />
  <link href="css/extralayers.css" rel="stylesheet" type="text/css" />

  <!--Accordion-->
  <link href="css/accordion.css" rel="stylesheet" type="text/css" />

  <!--tabs-->
  <link href="css/tabs.css" rel="stylesheet" type="text/css" />

  <!--Owl Carousel-->
  <link href="css/owl.carousel.css" rel="stylesheet" type="text/css" />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
  <!-- Mobile Menu -->
  <link rel="stylesheet" type="text/css" href="css/jquery.mmenu.all.css" />
  <link rel="stylesheet" type="text/css" href="css/demo.css" />

  <!--PreLoader-->
  <link href="css/loader.css" rel="stylesheet" type="text/css" />
  <link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.3.0/css/all.min.css" />
  <!--Medical Guide Icons-->
  <link
    href="fonts/medical-guide-icons.css"
    rel="stylesheet"
    type="text/css" />
  <style>
    .get-touch {
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
    }

    .get-touch .title h5 {
      font-size: 1.2rem;
    }

    .get-touch .detail ul {
      padding-left: 0;
    }

    .get-touch .detail li {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 15px;
    }

    .get-touch .detail li i {
      font-size: 1.5rem;
    }

    .get-touch .detail li span {
      font-size: 1rem;
    }
  </style>
</head>

<script src="https://www.google.com/recaptcha/api.js" async defer></script>

<style>
  /* Footer styles */
  .footer {

    color: #e0e0e0;
    padding-top: 4rem;
  }

  .main-footer {
    width: 100%;
  }

  .title h5 {
    color: #ffffff;
    font-size: 1.25rem;
    margin-bottom: 1.5rem;
    font-weight: 600;
  }

  .text {
    color: #a0a0a0;
    line-height: 1.7;
  }

  .useful-links a {
    color: #e0e0e0;
    text-decoration: none;
    transition: color 0.3s ease;
  }

  .useful-links a:hover {
    color: #ffffff;
  }

  .get-touch i {
    color: #a0a0a0;
  }

  .get-touch a {
    color: #e0e0e0;
    text-decoration: none;
    transition: color 0.3s ease;
  }

  .get-touch a:hover {
    color: #ffffff;
  }


  /* Footer Bottom Styles */
  .footer-bottom {
    border-top: 1px solid rgba(255, 255, 255, 0.1);
    margin-top: 3rem;
  }

  .copyrights {
    font-size: 0.9rem;
    color: white;
  }

  .social-icons {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
  }

  .social-icon {
    color: #a0a0a0;
    font-size: 1.2rem;
    transition: color 0.3s ease;
  }






  .social-icon:hover {
    color: #ffffff;
  }

  @media (max-width: 768px) {
    .useful-links {
      padding-top: 2rem;
    }

    .social-icons {
      justify-content: center;
      margin-top: 1rem;
    }

    .copyrights {
      text-align: center;
      display: block;
      margin-bottom: 1rem;

    }
  }
</style>

<body>
  <div id="wrap">
    <!--Start PreLoader-->
    <div id="preloader">
      <div id="status">&nbsp;</div>
      <div class="loader">
        <h1>Loading...</h1>
        <span></span>
        <span></span>
        <span></span>
      </div>
    </div>
    <!--End PreLoader-->

    <!--Start Top Bar-->

    <!--Top Bar End-->

    <!--Start Header-->

    <header class="header">
      <div class="container">
        <div class="row">
          <div class="col-md-3">
            <a href="index.html" class="logo"><img src="images/newlogo.webp" alt="" /></a>
          </div>

          <div class="col-md-9">
            <nav class="menu-2">
              <ul class="nav wtf-menu">
                <li class=""><a href="index.html">Home</a></li>

                <li class=""><a href="about-us.html">About Us</a></li>

                <li class="">
                  <a href="">Specilaties</a>
                  <ul class="submenu">
                    <li class="select">
                      <a href="./ObstetricsandGynecology.html">OBJ</a>
                    </li>
                    <li><a href="./Orthopedic.html">Orthopedic</a></li>
                    <li>
                      <a href="./genral-medicine.html">GenralMedicine</a>
                    </li>
                    <li><a href="./general-surgery.html">GenralSurgery</a></li>
                    <li><a href="./gynacology.html">Gynacology</a></li>
                    <li>
                      <a href="./diabetology.html">Diabetology</a>
                    </li>
                    <li><a href="./pediatric.html">Pediatric Clinic</a></li>
                    <li><a href="./">SpineCare Clinic</a></li>
                    <li><a href="./spinecare-clinic.html">Dermatology</a></li>



                </li>
              </ul>
              </li>

              <li class=""><a href="news-sidebar.html">Blogs</a></li>

              <!-- <li><a href="procedures.html">Procedures</a></li>
                  <li><a href="news-sidebar.html">Blogs</a></li>
                  <li class="parent">
                    <a href="gallery-nimble-three.html">Gallery</a>
                  </li> -->

              <li class="item-select parent">
                <a href="contact-us2.php">Contact Us</a>
              </li>

              <li class="parent">
                <a href="gallery-simple-three.html">Gallery</a>
              </li>
              </ul>
            </nav>
          </div>
        </div>
      </div>
    </header>

    <!--End Header-->

    <!-- Mobile Menu Start -->
    <div class="container">
      <div id="page">
        <header class="header">
          <a href="#menu"></a>
        </header>

        <nav id="menu">
          <ul>
            <li class="">
              <a href="index2.html">Home</a>
            </li>
            <li class="">
              <a href="about-us.html">About</a>
            </li>
            <li class="">
              <a href="#.">Specilaties</a>
              <ul class="submenu">
                <li class="select">
                  <a href="./ObstetricsandGynecology.html">OBJ</a>
                </li>
                <li><a href="./Orthopedic.html">Orthopedic</a></li>
                <li>
                  <a href="./genral-medicine.html">GenralMedicine</a>
                </li>
                <li><a href="./general-surgery.html">GenralSurgery</a></li>
                <li><a href="./gynacology.html">Gynacology</a></li>
                <li>
                  <a href="./diabetology.html">Diabetology</a>
                </li>
                <li><a href="./pediatric.html">PediatricClinic</a></li>
                <li><a href="./spinecare-clinic.html">SpineCare Clinic</a></li>
                <li><a href="./d">Dermatology</a></li>
                <li><a href="./Neurology.html">Neurology</a></li>
                <li>
                  <a href="./NeuroAndSpine.html">NeuroAndSpine Surgery</a>
                </li>
                <li>
                  <a href="./PlasticAndBurn.html">Plastic And Burn Surgery</a>
                </li>
              </ul>
            </li>

            <li class=""><a href="news-sidebar.html">Blogs</a></li>
            <li>
              <!-- <a href="gallery-nimble-three.html">Gallery</a> -->
            </li>

            <li class="select">
              <a href="contact-us2.php">Contact Us</a>
            </li>
            <li>
              <a href="./gallery-simple-three.html">Gallery</a>
            </li>
          </ul>
        </nav>
      </div>
    </div>
  </div>
  <!-- Mobile Menu End -->

  <!--Start Banner-->

  <div class="sub-banner">
    <!-- <img class="banner-img" src="images/breadcrumb2.png" alt="" /> -->
    <div class="detail">
      <div class="container">
        <div class="row">
          <div class="col-md-12" style="display: flex; justify-content: center">
            <div class="paging">
              <h2>Contact Us</h2>
              <ul>
                <li><a href="index2.html">Home</a></li>
                <li><a>Contact Us</a></li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!--End Banner-->

  <!--Start Content-->
  <div class="content">
    <div class="contact-us">


      <div class="leave-msg dark-back">
        <div class="container">
          <div class="rox">
            <div class="col-md-7">
              <div class="main-title">
                <h2>
                  <span>We'd</span> Love to <span>Hear From You</span>
                </h2>
                <p>
                  At Kaade Hospital, we value your feedback and are happy to assist you with any inquiries. Please fill out the form below to get in touch with us.
                </p>


              </div>

              <div class="form">
                <div class="row">
                  <p class="success" id="success" style="display: none"></p>
                  <p class="error" id="error" style="display: none"></p>
                  <form name="contact_form" id="contact_form"
                    method="post"
                    action="./sendmail.php">
                    <div class="col-md-4">
                      <input
                        type="text"
                        data-delay="300"
                        placeholder="Your full name"
                        name="name"
                        id="contact_name"
                        class="input" />
                    </div>
                    <div class="col-md-4">
                      <input
                        type="text"
                        data-delay="300"
                        placeholder="E-mail Address"
                        name="email"
                        id="contact_email"
                        class="input" />
                    </div>
                    <div class="col-md-4">
                      <input
                        type="text"
                        data-delay="300"
                        placeholder="Subject"
                        name="subject"
                        id="contact_subject"
                        class="input" />
                    </div>
                    <div class="col-md-12">
                      <textarea
                        data-delay="500"
                        class="required valid"
                        placeholder="Message"
                        name="message"
                        id="message"></textarea>
                    </div>
                    <div class="col-md-12">
                      <div class="g-recaptcha"
                        data-sitekey="6Ldgj0YrAAAAACSBwwRiE3Z5QRnqO03DJm9znXOG"></div>
                    </div>
                    <div class="col-md-3">
                      <input
                        name="send"
                        type="submit"
                        value="submit" />
                    </div>
                  </form>
                </div>
              </div>
            </div>

            <div class="col-md-5">
              <div class="contact-get">
                <div class="main-title">
                  <h2><span>GET IN</span> Touch</h2>
                  <p>
                    Kaade Hospital is committed to providing quality healthcare services. Contact us today.
                  </p>

                </div>

                <div class="get-in-touch">
                  <div class="detail">
                    <span><b>Phone:</b>+91 080 23500244 / 99022 53636</span>
                    <span><b>Email: </b>
                      <a href="mailto:kaadehelpdesk@gmail.com"> kaadehelpdesk@gmail.com</a></span>

                    <span><b>Address:</b> No.320/C & 321/A, 1st Stage, 2nd Phase, West Of Chord Road, Manjunatha Nagar, Bangalore - 560010
                    </span>
                  </div>

                  <div class="social-icons">
                    <a href="https://www.facebook.com/profile.php?id=61571028887970" target="_blank" class="fb"><i class="icon-euro"></i></a>
                    <a href="https://www.instagram.com/kaadehospital/" target="_blank" class="gp"><i class="icon-instagram2"></i></a>

                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="container">
        <div class="row">
          <div class="col-md-12">
            <div class="our-location">
              <div class="map">
                <iframe
                  src="https://www.google.com/maps/embed?pb=!1m14!1m8!1m3!1d15550.46459479305!2d77.5464271!3d12.9963854!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3bae3d66511f073f%3A0x2f7825ef54c7dcfb!2sKaade%20Hospital!5e0!3m2!1sen!2sin!4v1737712855389!5m2!1sen!2sin"
                  width="600"
                  height="450"
                  style="border: 0"
                  allowfullscreen=""
                  loading="lazy"
                  referrerpolicy="no-referrer-when-downgrade"></iframe>
              </div>
              <!-- <div class="get-directions">
                <form
                  action="http://maps.google.com/maps"
                  method="get"
                  target="_blank">
                  <input
                    type="text"
                    name="saddr"
                    placeholder="Enter Your Address" />
                  <input
                    type="hidden"
                    name="daddr"
                    value="Kaade Hospital ,Thimmaiah Rd, Manjunath Nagar, Basaveshwar Nagar, Bengaluru, Karnataka 560010" />
                  <input
                    type="submit"
                    value="Get directions"
                    class="direction-btn" />
                </form>
              </div> -->
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <!--End Content-->

  <!--Start Footer-->
  <footer class="footer" id="footer" style="margin-top: 25px">
    <div class="container">
      <!-- Main Footer Section -->

      <div class="row"></div>
      <div class="footer-center">
        <div class="main-footer">
          <div class="row g-4">
            <div class="col-md-4">
              <div class="get-touch">
                <a href="./index.html">
                  <img
                    class="footer-image img-fluid rounded"
                    src="images/newlogo.webp"
                    alt="Company Logo" />
                </a>
                <div class="detail">
                  <div class="get-touch">
                    <span class="text">Kaade Hospital today stands as a testimony to a
                      commitment of competent and affordable medical care
                      thus giving the best outcome, for everyone,
                      everytime.</span>
                  </div>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <div class="useful-links">
                <div class="title">
                  <h5>Useful Links</h5>
                </div>
                <div class="detail">
                  <ul class="">
                    <li class="mb-2"><a href="./index2.html">Home</a></li>
                    <li class="mb-2">
                      <a href="./about-us.html">About</a>
                    </li>
                    <li class="mb-2">
                      <a href="./service3.html">Services</a>
                    </li>
                    <li class="mb-2">
                      <a href="./news-sidebar.html">Blogs</a>
                    </li>
                    <li class="mb-2">
                      <a href="./contact-us2.php">Contact</a>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <div class="get-touch">
                <div class="title" style="margin-top: 5px">
                  <h5>GET IN TOUCH</h5>
                </div>
                <div class="ded">
                  <ul class="list-unstyled" style="margin-top: 35px">
                    <li class="d-flex align-items-center gap-3">
                      <i class="fas fa-map-marker-alt mt-1"></i>
                      <span>West Of Chord Road, Manjunatha Nagar,
                        Bangalore</span>
                    </li>
                    <li class="d-flex align-items-center gap-3 mb-3">
                      <i class="fas fa-phone mt-1"></i>
                      <span>+91 080 23500244 /99022 53636</span>
                    </li>
                    <li class="d-flex align-items-center gap-3">
                      <i class="fas fa-envelope mt-1"></i>
                      <a href="mailto:kaadehelpdesk@gmail.com">
                        <span>kaadehelpdesk@gmail.com</span>
                      </a>
                    </li>

                    <li class="d-flex align-items- gap-3">
                      <a
                        href="https://www.instagram.com"
                        target="_blank"
                        class="text-decoration-none">
                        <i class="fab fa-instagram"></i>
                      </a>
                      <a
                        href="https://www.facebook.com"
                        target="_blank"
                        class="text-decoration-none">
                        <i class="fab fa-facebook-f"></i>
                      </a>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- <div class="col-md-4">
            <div class="get-touch" >
              <div class="title" style="margin-top: 25px;">
                <h5>GET IN TOUCH</h5>
              </div>
              <div class="detail">
                <div class="get-touch">
               
                  <ul class="list-unstyled ">
                    <li class="d-flex align-items-start gap-3 ">
                      <i class="fas fa-map-marker-alt mt-1"></i>
                      <span>West Of Chord Road, Manjunatha Nagar, Bangalore</span>
                    </li>
                    <li class="d-flex align-items-start gap-3 mb-3">
                      <i class="fas fa-phone mt-1"></i>
                      <span>+91 080 23500244 /99022 53636</span>
                    </li>
                    <li class="d-flex align-items-start gap-3">
                      <i class="fas fa-envelope mt-1"></i>
                      <a href="mailto:kaadehospitalblr@gmail.com">
                        <span>kaadehospitalblr@gmail.com</span>
                      </a>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div> -->

      <!-- Footer Bottom Section -->
      <div class="py-3" id="bottom">
        <div class="row align-items-center">
          <div class="col-md-6">
            <span class="copyrights" style="color: #6c757d">
              Copyright &copy; <span id="copyright"></span> Kaade Hospital.
              Made with ❤️ by
              <a
                style="color: orange"
                href="https://sunrisedigital.co.in/"
                target="_blank">sunrise Digital Media
              </a>
            </span>
          </div>
        </div>
      </div>
    </div>
  </footer>
  <!--End Footer-->
  </div>

  <a href="#0" class="cd-top"></a>

  <script type="text/javascript" src="js/jquery.js"></script>

  <!-- SMOOTH SCROLL -->
  <script type="text/javascript" src="js/scroll-desktop.js"></script>
  <script type="text/javascript" src="js/scroll-desktop-smooth.js"></script>

  <!-- START REVOLUTION SLIDER -->
  <script
    type="text/javascript"
    src="js/jquery.themepunch.revolution.min.js"></script>
  <script
    type="text/javascript"
    src="js/jquery.themepunch.tools.min.js"></script>

  <!-- Date Picker and input hover -->
  <script type="text/javascript" src="js/classie.js"></script>
  <script type="text/javascript" src="js/jquery-ui-1.10.3.custom.js"></script>

  <!-- Welcome Tabs -->
  <script type="text/javascript" src="js/tabs.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script>
    const currentYear = new Date().getFullYear();

    document.getElementById('copyright').textContent = currentYear;
  </script>

  <!-- All Carousel -->
  <script type="text/javascript" src="js/owl.carousel.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <!-- Mobile Menu -->
  <script type="text/javascript" src="js/jquery.mmenu.min.all.js"></script>

  <!-- All Scripts -->
  <script type="text/javascript" src="js/custom.js"></script>

  <!-- php starts here  -->
  <?php

  use PHPMailer\PHPMailer\PHPMailer;
  use PHPMailer\PHPMailer\SMTP;
  use PHPMailer\PHPMailer\Exception;

  if (isset($_POST['send'])) {

    $name = $_POST['name'];
    $email = $_POST['email'];
    $subject = $_POST['subject'];
    $message = $_POST['message'];

    // Load Composer's autoloader
    require 'php/PHPMailer/Exception.php';
    require 'php/PHPMailer/PHPMailer.php';
    require 'php/PHPMailer/SMTP.php';

    // Create an instance; passing `true` enables exceptions
    $mail = new PHPMailer(true);

    try {
      // Server settings
      $mail->SMTPDebug = SMTP::DEBUG_OFF; // Disable verbose debug output
      $mail->isSMTP();                    // Send using SMTP
      $mail->Host       = 'smtp.gmail.com'; // Set the SMTP server to send through
      $mail->SMTPAuth   = true;            // Enable SMTP authentication
      $mail->Username   = 'adityakulkarni54321@gmail.com'; // SMTP username
      $mail->Password   = 'wler orjy isro kvju';           // SMTP password
      $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;     // Enable implicit TLS encryption
      $mail->Port       = 465;                             // TCP port to connect to

      // Recipients
      $mail->setFrom('adityakulkarni54321@gmail.com', 'Hospital Contact Form');
      $mail->addAddress('adityakn60@gmail.com', 'Hospital Admin'); // Recipient email address
      $mail->addReplyTo($email, $name);                  // Reply-To address from the form input

      // Content
      $mail->isHTML(true);            // Set email format to HTML
      $mail->Subject = $subject;      // Use the subject from the form input
      $mail->Body    = "<p><strong>Name:</strong> {$name}</p>
                          <p><strong>Email:</strong> {$email}</p>
                          <p><strong>Message:</strong></p>
                          <p>{$message}</p>";

      $mail->send();
      echo '<script>
                Swal.fire({
                    title: "Message Sent",
                    text: "Thank you for contacting us. We will get back to you soon.",
                    icon: "success",
                    confirmButtonText: "OK"
                });
              </script>';
    } catch (Exception $e) {
      echo "<script>
                Swal.fire({
                    title: 'Error',
                    text: 'Message could not be sent. Mailer Error: {$mail->ErrorInfo}',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
              </script>";
    }
  }

  ?>




</body>

</html>