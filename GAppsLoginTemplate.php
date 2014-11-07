<?php
/**
 * Html form for GApps login.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 */

class GAppsLoginTemplate extends BaseTemplate {

	function execute() {
		global $wgCookieExpiration, $wgGAppsDomains;
		$expirationDays = ceil( $wgCookieExpiration / ( 3600 * 24 ) );
?>
<div class="mw-ui-container">
    <?php if ( $this->haveData( 'languages' ) ):?>
        <div id="languagelinks">
            <p><?php $this->html( 'languages' ); ?></p>
        </div>
    <?php endif; ?>
    <div id="userloginForm">
        <form name="userlogin" class="mw-ui-vform" method="get" action="/index.php/Special:UserLogin">
            <section class="mw-form-header">
                <?php $this->html( 'header' ); /* extensions such as ConfirmEdit add form HTML here */ ?>
            </section>
            <div>
                <label for="DomainSelect" class="mw-ui-block">Please select Google Apps Domain:</label>
                <select id="DomainSelect" name="gapps_domain">
                    <?php foreach ($wgGAppsDomains as $domain):?>
                        <option value="<?php echo $domain;?>">
                            <?php echo $domain;?>
                        </option>
                    <?php endforeach;?>
                </select>
            </div>
            <div>
                <?php
                    echo Html::input(
                        '', 
                        'select',
                        'submit', array(
                            'id' => 'wpLoginAttempt',
                            'tabindex' => '6',
                            'class' => 'mw-ui-button mw-ui-block mw-ui-primary'
                        ));
                ?>
            </div>
            <input type="hidden" name="returnto" value="Special:Userlogin" />
        </form>
    </div>
</div>
<?php }}
