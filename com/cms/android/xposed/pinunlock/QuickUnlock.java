package com.cms.android.xposed.pinunlock;

import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.Arrays;

import android.text.Editable;
import android.text.TextWatcher;
import android.widget.TextView;

import com.android.internal.widget.LockPatternUtils;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * 
 * @author PongLenis (try.nslookup.this at gmail.com)
 * 
 * 
 *         2013-07-20 2013-07-28
 * 
 */
public class QuickUnlock implements IXposedHookLoadPackage {

   /**
    * Packages
    */
   private static final String PKG_ANDROID = "android";

   /**
    * Classes
    */
   private static final String CLS_KeyguardPINView = "com.android.internal.policy.impl.keyguard.KeyguardPINView";
   private static final String CLS_KeyguardAbsKeyInputView = "com.android.internal.policy.impl.keyguard.KeyguardAbsKeyInputView";

   /**
    * Methods
    */
   private static final String MTD_verifyPasswordAndUnlock = "verifyPasswordAndUnlock";
   private static final String MTD_onFinishInflate = "onFinishInflate";

   /**
    * Fields
    */
   private static final String FLD_mPasswordEntry = "mPasswordEntry";
   private static final String FLD_mLockPatternUtils = "mLockPatternUtils";

   /**
    * Misc.
    */
   private static final String SYSTEM_DIRECTORY = "/system/";
   private static final String LOCK_PASSWORD_FILE = "password.key";

   private static final int MIN_PIN_LENGTH = 4;

   /**
    * Main
    */
   @Override
   public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
      if (PKG_ANDROID.equals(lpparam.packageName)) {
         enablePinQuickUnlock(lpparam.classLoader != null ? lpparam.classLoader : XposedBridge.BOOTCLASSLOADER);
      }
   }

   /**
    * Logic
    */
   private static void enablePinQuickUnlock(final ClassLoader cl) {

      /**
       * Retrieve classes/methods which we want to override
       */
      final Class<?> KeyguardPINView = XposedHelpers.findClass(CLS_KeyguardPINView, cl);
      final Class<?> KeyguardAbsKeyInputView = XposedHelpers.findClass(CLS_KeyguardAbsKeyInputView, cl);

      final Method verifyPasswordAndUnlock = XposedHelpers.findMethodExact(KeyguardAbsKeyInputView, MTD_verifyPasswordAndUnlock);

      XposedHelpers.findAndHookMethod(KeyguardPINView, MTD_onFinishInflate, new XC_MethodHook() {

         @Override
         protected void afterHookedMethod(final MethodHookParam param) throws Throwable {

            final TextView mPasswordEntry = (TextView) XposedHelpers.getObjectField(param.thisObject, FLD_mPasswordEntry);
            final LockPatternUtils mLockPatternUtils = (LockPatternUtils) (XposedHelpers.getObjectField(param.thisObject, FLD_mLockPatternUtils));
            final byte[] storedPinHash = retrieveStoredPinHash();

            /**
             * Check if we got an exception retrieving the Pin from file.
             * Return if we did. Guess we screwed up. The user can still tap
             * "OK" to unlock at this point, so no worries.
             */
            if (storedPinHash == null) {
               return;
            }

            /**
             * Let's add a new TextWatcher to the mPasswordEntry field in
             * KeyguardPINView.onFinishInflate()
             */
            mPasswordEntry.addTextChangedListener(new TextWatcher() {

               @Override
               public void afterTextChanged(final Editable pin) {

                  /**
                   * Avoid unnecessary method calls involved in pin
                   * verification if the entered pin length is < 4.
                   */
                  if (pin.length() < MIN_PIN_LENGTH) {
                     return;
                  }

                  /**
                   * Get the hash for the entered pin
                   */
                  final byte[] pinHash = mLockPatternUtils.passwordToHash(pin.toString());

                  /**
                   * Call verifyPasswordAndUnlock() if the entered pins
                   * hash is == the stored pins hash.
                   */
                  if (Arrays.equals(storedPinHash, pinHash)) {
                     try {
                        XposedBridge.invokeOriginalMethod(verifyPasswordAndUnlock, param.thisObject, null);

                     } catch (final Exception e) {
                        e.printStackTrace();
                        XposedBridge.log(e);
                     }
                  }
               }

               /**
                * Misc. overrides
                */
               @Override
               public void onTextChanged(final CharSequence s, final int start, final int before, final int count) {
               }

               @Override
               public void beforeTextChanged(final CharSequence s, final int start, final int count, final int after) {
               }
            });
         }
      });
   }

   /**
    * Retrieve actual pin (from password.key) to get its length
    * 
    * WARNING:
    * 
    * @see com.android.internal.widget.LockSettingsService#checkPassword(com.android.internal.widget.LockSettingsService)
    * 
    *      We are assuming userId = 0 here. I.e. for multi-user enabled 4.2.2
    *      roms this will only work for the first/owner user account.
    * 
    *      Other user accounts will not be able to unlock their devices via pin
    *      unlock unless their pin is equal to the device owners pin.
    * 
    *      This happens because each user's password.key file is stored in a
    *      separate folder and I don't know how to retrieve the user id at this
    *      point.
    * 
    * @return the pin/password hash saved for userid0 in
    *         /data/system/password.key
    * 
    *         or null if an exception was thrown during file retrieval
    */
   private static byte[] retrieveStoredPinHash() {

      final String dataSystemDirectory = android.os.Environment.getDataDirectory().getAbsolutePath() + SYSTEM_DIRECTORY;
      RandomAccessFile raf = null;
      byte[] storedPinHash = null;

      try {
         raf = new RandomAccessFile(dataSystemDirectory + LOCK_PASSWORD_FILE, "r");
         storedPinHash = new byte[(int) raf.length()];

         raf.read(storedPinHash, 0, storedPinHash.length);
         raf.close();

         return storedPinHash;

      } catch (final Exception e) {
         XposedBridge.log(dataSystemDirectory + LOCK_PASSWORD_FILE);

         /**
          * Ok, we screwed up somewhere during file retrieval, let's just
          * return null and let the caller handle it.
          */
         return null;
      }
   }
}
