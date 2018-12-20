<?php

namespace App\Http\Controllers\Auth;

use Validator;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\User;
use App\PasswordReset;
use App\Notifications\PasswordResetRequest;
use Carbon\Carbon;
use App\Notifications\PasswordResetSuccess;

class PasswordResetController extends Controller
{
    /**
     * Create password reset token
     *
     * @param Request $request
     * @return string JSON
     */
    public function create(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json(['message' => "We can't find a user with that e-mail address."], 404);
        }

        $passwordReset = PasswordReset::updateOrCreate(
            [
                'email' => $user->email
            ],
            [
                'email' => $user->email,
                'token' => str_random(60)
            ]
        );

        if ($user && $passwordReset) {
            $user->notify(new PasswordResetRequest($passwordReset->token));
            return response()->json(['message' => 'We have e-mailed your password reset link!']);
        }
    }

    /**
     * Validate password reset token
     *
     * @param string $token
     * @return array
     */
    public function find($token)
    {
        $passwordReset = PasswordReset::where('token', $token)->first();

        if (!$passwordReset) {
            return response()->json(['message' => 'This password reset token is invalid.'], 404);
        }

        if (Carbon::parse($passwordReset->updated_at)->addMinutes(120)->isPast()) {
            $passwordReset->delete();
            return response()->json(['message' => 'This password reset token is invalid.'], 404);
        }

        return response()->json($passwordReset);
    }

    /**
     * Reset password
     *
     * @param Request $request
     * @return array
     */
    public function reset(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string|confirmed',
            'token' => 'required|string'
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], 422);
        }

        $passwordReset = PasswordReset::where([
            ['token', $request->token],
            ['email', $request->email]
        ])->first();

        if (!$passwordReset) {
            return response()->json(['message' => 'This password reset token is invalid.'], 404);
        }

        $user = User::where('email', $passwordReset->email)->first();

        if (!$user) {
            return response()->json(['message' => "We can't find a user with that e-mail address."], 404);
        }

        $user->password = bcrypt($request->password);
        $user->save();

        $passwordReset->delete();

        $user->notify(new PasswordResetSuccess($passwordReset));

        return response()->json($user);
    }
}
