<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\Sentinel\Concerns\HasMultiFactorAuthentication;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Override;

/**
 * Test user model.
 *
 * @property string $email
 * @property int    $id
 * @property string $name
 * @property string $password
 * @author Brian Faust <brian@cline.sh>
 */
final class User extends Authenticatable
{
    use HasFactory;
    use HasMultiFactorAuthentication;

    /** @var bool */
    #[Override()]
    public $timestamps = false;

    /** @var string */
    #[Override()]
    protected $table = 'users';

    /** @var array<int, string> */
    #[Override()]
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * @return array<string, string>
     */
    #[Override()]
    protected function casts(): array
    {
        return [
            'password' => 'hashed',
        ];
    }
}
