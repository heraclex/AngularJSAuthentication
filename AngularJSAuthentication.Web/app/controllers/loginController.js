// this controller will be responsible to redirect authenticated users only to the orders view, 
// if you tried to request the orders view as anonymous user, you will be redirected to log-in view. 
// We’ll see in the next steps how we’ll implement the redirection for anonymous users to the log-in view once users request a secure view.
'use strict';
app.controller('loginController', ['$scope', '$location', 'authService', function ($scope, $location, authService) {

    $scope.loginData = { userName: "", password: "" };

    $scope.message = "";

    $scope.login = function () {

        authService.login($scope.loginData).then(function (response) {

            $location.path('/orders');

        },
         function (err) {
             $scope.message = err.error_description;
         });
    };

}]);