<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\User;
use Validator;
use App\Notifications\SignupActivate;

class AuthController extends Controller
{
    /**
     * Create user
     *
     * @param Request $request
     * @return string JSON
     */
    public function signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], 422);
        }

        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'activation_token' => str_random(60)
        ]);

        $user->save();

        $user->notify(new SignupActivate($user));

        return response()->json(['message' => 'Successfully created user!'], 201);
    }


    public function signupActivate($token)
    {
        $user = User::where('activation_token', $token)->first();

        if (!$user) {
            return response()->json(['message' => 'This activation token is invalid.'], 404);
        }

        $user->email_verified_at = Carbon::now();
        $user->active = true;
        $user->activation_token = '';
        $user->save();

        return response()->json(['message' => 'Successfully activated user!'], 201);
    }

    /**
     * Login user and create token
     *
     * @param Request $request
     * @return string JSON
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], 422);
        }

        $credentials = request(['email', 'password']);
        $credentials['deleted_at'] = null;

        if (Auth::attempt($credentials)) {
            if ($request->user()->active == 0) {
                return response()->json(['message' => 'Please confirm your account'], 401);
            }
        } else {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;

        if ($request->remember_me) {
            $token->expires_at = Carbon::now()->addWeeks(1);
        }

        $token->save();

        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }

    /**
     * Logout user (Revoke the token)
     *
     * @param Request $request
     * @return string JSON
     */
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Get authenticated user
     *
     * @param Request $request
     * @return string JSON
     */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

}
