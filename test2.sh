set -x

cd /Users/ctos/workspace/pratikbin/hacks/oc-secret-mask-test

echo ""
echo "# TEST 2"
echo ""
cat >secret-test.txt<<EOF
this is fake aws secret
\`\`\`
AKIARVOALFPMFEW3SVMW
\`\`\`
don't worry
EOF
export OPENCODE_REDACTOR_AUDIT_ENABLED=1
export OPENCODE_REDACTOR_AUDIT_PATH="$PWD/test2.audit.jsonl"
echo > "$OPENCODE_REDACTOR_AUDIT_PATH"
opencode run "Read secret-test.txt, print it's content and add 'this is super secret' at it's end " --model deepseek/deepseek-chat

echo ""
echo "# TEST 2: audit result"
echo ""
cat $OPENCODE_REDACTOR_AUDIT_PATH
